package pulseclient

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"testing"
)

type conformanceFixture struct {
	Schema           string            `json:"schema"`
	SchemaVersion    int               `json:"schema_version"`
	WireVersion      int               `json:"wire_version"`
	ApplicationClose map[string]string `json:"application_close"`
	Control          struct {
		InitialAckFramedHex           string `json:"initial_ack_framed_hex"`
		UpdateAckFramedHex            string `json:"update_ack_framed_hex"`
		UpdateAckWithVersionFramedHex string `json:"update_ack_with_version_framed_hex"`
		InitialSigFirstJSON           string `json:"initial_sig_first_json"`
	} `json:"control"`
	Vectors struct {
		StreamPreamble struct {
			Hex string `json:"hex"`
		} `json:"stream_preamble"`
		SigFirstDatagram struct {
			Hex          string `json:"hex"`
			Slot         uint64 `json:"slot"`
			Seq          uint64 `json:"seq"`
			SignatureHex string `json:"signature_hex"`
		} `json:"sig_first_datagram"`
		DatagramHeartbeat struct {
			Hex        string `json:"hex"`
			ServerTsMs uint64 `json:"server_ts_ms"`
			HighestSeq uint64 `json:"highest_seq"`
		} `json:"datagram_heartbeat"`
		FullTxBare       conformanceFullTx `json:"full_tx_bare"`
		FullTxEnriched   conformanceFullTx `json:"full_tx_enriched"`
		FullTxUnknownTLV struct {
			FrameHex        string `json:"frame_hex"`
			UnknownType     uint8  `json:"unknown_type"`
			UnknownValueHex string `json:"unknown_value_hex"`
		} `json:"full_tx_unknown_tlv"`
		StreamHeartbeat struct {
			FrameHex        string `json:"frame_hex"`
			StreamRecordHex string `json:"stream_record_hex"`
			ServerTsMs      uint64 `json:"server_ts_ms"`
			HighestSeq      uint64 `json:"highest_seq"`
		} `json:"stream_heartbeat"`
	} `json:"vectors"`
}

type conformanceFullTx struct {
	FrameHex          string   `json:"frame_hex"`
	StreamRecordHex   string   `json:"stream_record_hex"`
	Slot              uint64   `json:"slot"`
	AltIncomplete     bool     `json:"alt_incomplete"`
	LoadedWritableHex []string `json:"loaded_writable_hex"`
	LoadedReadonlyHex []string `json:"loaded_readonly_hex"`
}

func TestSharedWireV2ConformanceVectors(t *testing.T) {
	fixture := loadConformanceFixture(t)
	if fixture.Schema != "thornode.pulse.wire-v2.conformance" || fixture.SchemaVersion != 1 {
		t.Fatalf("unsupported conformance schema %q v%d", fixture.Schema, fixture.SchemaVersion)
	}
	if fixture.WireVersion != WireVersion {
		t.Fatalf("fixture wire version = %d, SDK = %d", fixture.WireVersion, WireVersion)
	}

	t.Run("application close policy", func(t *testing.T) {
		want := map[string]RetryClass{
			"normal":               RetryNormal,
			"non_retryable":        RetryNever,
			"credentials_required": RetryAfterCredentialChange,
			"transient":            RetryTransient,
		}
		for rawCode, rawClass := range fixture.ApplicationClose {
			code, err := strconv.ParseUint(rawCode, 10, 64)
			if err != nil {
				t.Fatalf("parse close code %q: %v", rawCode, err)
			}
			expected, ok := want[rawClass]
			if !ok {
				t.Fatalf("fixture uses unknown retry class %q", rawClass)
			}
			if got := ClassifyCloseCode(ApplicationCloseCode(code)); got != expected {
				t.Fatalf("close code %d = %s, fixture wants %q", code, got, rawClass)
			}
		}
	})

	t.Run("control", func(t *testing.T) {
		body, err := json.Marshal(control{
			Filter: AllNonVoteTxs(),
			Token:  "example-token",
			Full:   false,
			V:      WireVersion,
			Fields: []string{},
		})
		if err != nil {
			t.Fatalf("marshal control: %v", err)
		}
		if string(body) != fixture.Control.InitialSigFirstJSON {
			t.Fatalf("control = %s\nfixture = %s", body, fixture.Control.InitialSigFirstJSON)
		}

		ack, err := readAck(bytes.NewReader(mustHex(t, fixture.Control.InitialAckFramedHex)))
		if err != nil {
			t.Fatalf("read initial ack: %v", err)
		}
		if _, err := checkInitialAck(ack); err != nil {
			t.Fatalf("check initial ack: %v", err)
		}
		if ack.V == nil || *ack.V != WireVersion {
			t.Fatalf("ack wire version = %v", ack.V)
		}

		for name, encoded := range map[string]string{
			"without version":  fixture.Control.UpdateAckFramedHex,
			"matching version": fixture.Control.UpdateAckWithVersionFramedHex,
		} {
			ack, err := readAck(bytes.NewReader(mustHex(t, encoded)))
			if err != nil {
				t.Fatalf("read update ack %s: %v", name, err)
			}
			if _, err := checkUpdateAck(ack); err != nil {
				t.Fatalf("check update ack %s: %v", name, err)
			}
		}
	})

	t.Run("stream preamble", func(t *testing.T) {
		preamble := mustHex(t, fixture.Vectors.StreamPreamble.Hex)
		if !bytes.Equal(preamble, []byte(Preamble)) {
			t.Fatalf("Preamble = %x, fixture = %x", Preamble, preamble)
		}
		if err := verifyPreamble(bytes.NewReader(preamble)); err != nil {
			t.Fatalf("verifyPreamble: %v", err)
		}
	})

	t.Run("sig-first datagram", func(t *testing.T) {
		vector := fixture.Vectors.SigFirstDatagram
		decoded, err := DecodeDatagram(mustHex(t, vector.Hex))
		if err != nil {
			t.Fatalf("DecodeDatagram: %v", err)
		}
		item, ok := decoded.(SigFirst)
		if !ok {
			t.Fatalf("decoded %T, want SigFirst", decoded)
		}
		if item.Slot != vector.Slot || item.Seq != vector.Seq || hex.EncodeToString(item.Signature[:]) != vector.SignatureHex {
			t.Fatalf("decoded sig-first = %+v", item)
		}
	})

	t.Run("datagram heartbeat", func(t *testing.T) {
		vector := fixture.Vectors.DatagramHeartbeat
		decoded, err := DecodeDatagram(mustHex(t, vector.Hex))
		if err != nil {
			t.Fatalf("DecodeDatagram: %v", err)
		}
		heartbeat, ok := decoded.(DatagramHeartbeat)
		if !ok || heartbeat.ServerTsMs != vector.ServerTsMs || heartbeat.HighestSeq != vector.HighestSeq {
			t.Fatalf("decoded heartbeat = %+v", decoded)
		}
	})

	t.Run("bare full transaction", func(t *testing.T) {
		assertConformanceFullTx(t, fixture.Vectors.FullTxBare)
	})

	t.Run("enriched full transaction", func(t *testing.T) {
		assertConformanceFullTx(t, fixture.Vectors.FullTxEnriched)
	})

	t.Run("unknown TLV", func(t *testing.T) {
		vector := fixture.Vectors.FullTxUnknownTLV
		frame, err := DecodeFrame(mustHex(t, vector.FrameHex))
		if err != nil {
			t.Fatalf("unknown TLV type %d value %s must be skipped: %v", vector.UnknownType, vector.UnknownValueHex, err)
		}
		if _, ok := frame.(FullTxV2); !ok {
			t.Fatalf("decoded %T, want FullTxV2", frame)
		}
	})

	t.Run("stream heartbeat", func(t *testing.T) {
		vector := fixture.Vectors.StreamHeartbeat
		frame, err := DecodeFrame(mustHex(t, vector.FrameHex))
		if err != nil {
			t.Fatalf("DecodeFrame: %v", err)
		}
		heartbeat, ok := frame.(FrameHeartbeat)
		if !ok || heartbeat.ServerTsMs != vector.ServerTsMs || heartbeat.HighestSeq != vector.HighestSeq {
			t.Fatalf("decoded heartbeat = %+v", frame)
		}

		var observed heartbeatState
		_, err = nextFrame(bytes.NewReader(mustHex(t, vector.StreamRecordHex)), &observed)
		if !errors.Is(err, io.EOF) {
			t.Fatalf("heartbeat-only record err = %v, want io.EOF after folding heartbeat", err)
		}
		if !observed.ok || observed.serverTsMs != vector.ServerTsMs || observed.highestSeq != vector.HighestSeq {
			t.Fatalf("folded heartbeat = %+v", observed)
		}
	})
}

func assertConformanceFullTx(t *testing.T, vector conformanceFullTx) {
	t.Helper()
	frameBytes := mustHex(t, vector.FrameHex)
	frame, err := DecodeFrame(frameBytes)
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	full, ok := frame.(FullTxV2)
	if !ok {
		t.Fatalf("decoded %T, want FullTxV2", frame)
	}
	if full.Tx.Slot != vector.Slot || full.AltIncomplete != vector.AltIncomplete {
		t.Fatalf("decoded slot/flags = %d/%v, want %d/%v", full.Tx.Slot, full.AltIncomplete, vector.Slot, vector.AltIncomplete)
	}
	if got, want := addressHex(full.LoadedWritable), vector.LoadedWritableHex; !reflect.DeepEqual(got, want) {
		t.Fatalf("loaded writable = %v, want %v", got, want)
	}
	if got, want := addressHex(full.LoadedReadonly), vector.LoadedReadonlyHex; !reflect.DeepEqual(got, want) {
		t.Fatalf("loaded readonly = %v, want %v", got, want)
	}

	var heartbeat heartbeatState
	streamFull, err := nextFrame(bytes.NewReader(mustHex(t, vector.StreamRecordHex)), &heartbeat)
	if err != nil {
		t.Fatalf("nextFrame: %v", err)
	}
	if streamFull.Tx.Slot != vector.Slot || streamFull.AltIncomplete != vector.AltIncomplete {
		t.Fatalf("stream record decoded = %+v", streamFull)
	}
}

func addressHex(addresses [][32]byte) []string {
	out := make([]string, len(addresses))
	for i := range addresses {
		out[i] = hex.EncodeToString(addresses[i][:])
	}
	return out
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode fixture hex: %v", err)
	}
	return decoded
}

func loadConformanceFixture(t *testing.T) conformanceFixture {
	t.Helper()
	if explicit := os.Getenv("PULSE_CONFORMANCE_VECTORS"); explicit != "" {
		return readConformanceFixture(t, explicit)
	}
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate conformance test source")
	}
	dir := filepath.Dir(sourceFile)
	candidates := []string{
		filepath.Join(dir, "..", "..", "conformance", "wire-v2", "vectors.json"),
		filepath.Join(dir, "conformance", "wire-v2", "vectors.json"),
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return readConformanceFixture(t, candidate)
		}
	}
	t.Fatal("shared wire-v2 vectors not found; set PULSE_CONFORMANCE_VECTORS or include conformance/wire-v2/vectors.json")
	return conformanceFixture{}
}

func readConformanceFixture(t *testing.T, path string) conformanceFixture {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read conformance fixture %s: %v", path, err)
	}
	var fixture conformanceFixture
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatalf("decode conformance fixture %s: %v", path, err)
	}
	return fixture
}
