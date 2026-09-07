package parquet_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/parquet-go/parquet-go"
)

type DebugEvent struct {
	ID      string `parquet:"id"`
	Payload []byte `parquet:"payload"`
}

func TestParquetDebug(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.parquet"

	// Write
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	writer := parquet.NewGenericWriter[DebugEvent](f)
	n, err := writer.Write([]DebugEvent{
		{ID: "event-1", Payload: []byte("payload-1")},
	})
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}
	fmt.Printf("Wrote %d events\n", n)

	// Flush and close writer
	if err := writer.Close(); err != nil {
		t.Fatalf("writer close failed: %v", err)
	}
	f.Close()

	// Check file size
	info, _ := os.Stat(path)
	fmt.Printf("File size: %d bytes\n", info.Size())

	// Read
	f2, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f2.Close()

	reader := parquet.NewGenericReader[DebugEvent](f2)
	buf := make([]DebugEvent, 10)
	n, err = reader.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %v (n=%d)", err, n)
	}

	fmt.Printf("Read %d events\n", n)
	for i := 0; i < n; i++ {
		fmt.Printf("  Event %d: ID=%s, Payload=%s\n", i, buf[i].ID, buf[i].Payload)
	}
}