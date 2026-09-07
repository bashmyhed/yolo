package parquet_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/parquet-go/parquet-go"
)

type TestEvent struct {
	ID      string `parquet:"id"`
	Payload []byte `parquet:"payload"`
}

func TestParquetBasic(t *testing.T) {
	// Write
	f, err := os.CreateTemp("", "test-*.parquet")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	writer := parquet.NewGenericWriter[TestEvent](f)
	_, err = writer.Write([]TestEvent{
		{ID: "event-1", Payload: []byte("payload-1")},
		{ID: "event-2", Payload: []byte("payload-2")},
	})
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}
	writer.Close()
	f.Close()

	// Read
	f2, err := os.Open(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer f2.Close()

	reader := parquet.NewGenericReader[TestEvent](f2)
	buf := make([]TestEvent, 2)
	n, err := reader.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	fmt.Printf("Read %d events\n", n)
	for i := 0; i < n; i++ {
		fmt.Printf("  Event %d: ID=%s, Payload=%s\n", i, buf[i].ID, buf[i].Payload)
	}
}