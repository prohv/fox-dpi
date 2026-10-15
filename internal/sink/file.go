package sink

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultMaxSizeBytes = 10 * 1024 * 1024 // 10 MB
	DefaultBufferSize   = 64 * 1024        // 64 KB
	DefaultQueueSize    = 8192
)

// FileSinkConfig configures the asynchronous rotating file sink.
type FileSinkConfig struct {
	OutputDir        string
	MaxSizeBytes     int64
	BufferSize       int
	QueueCapacity    int
	CompressOnRotate bool
}

// DefaultFileSinkConfig returns sensible production defaults.
func DefaultFileSinkConfig(outputDir string) FileSinkConfig {
	if outputDir == "" {
		outputDir = "."
	}
	return FileSinkConfig{
		OutputDir:        outputDir,
		MaxSizeBytes:     DefaultMaxSizeBytes,
		BufferSize:       DefaultBufferSize,
		QueueCapacity:    DefaultQueueSize,
		CompressOnRotate: true,
	}
}

// rotatingWriter manages buffered writing and size-based rotation with background gzip compression.
type rotatingWriter struct {
	dir         string
	baseName    string
	prefix      string
	maxSize     int64
	bufferSize  int
	currentSize int64
	seq         int
	compress    bool

	file   *os.File
	writer *bufio.Writer
	wg     sync.WaitGroup
}

func newRotatingWriter(dir, prefix string, maxSize int64, bufferSize int, compress bool) (*rotatingWriter, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create sink directory: %w", err)
	}

	rw := &rotatingWriter{
		dir:        dir,
		baseName:   prefix + ".jsonl",
		prefix:     prefix,
		maxSize:    maxSize,
		bufferSize: bufferSize,
		compress:   compress,
	}

	if err := rw.openCurrent(); err != nil {
		return nil, err
	}
	return rw, nil
}

func (r *rotatingWriter) openCurrent() error {
	path := filepath.Join(r.dir, r.baseName)
	fi, err := os.Stat(path)
	if err == nil {
		r.currentSize = fi.Size()
	} else {
		r.currentSize = 0
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open sink file %s: %w", path, err)
	}
	r.file = f
	r.writer = bufio.NewWriterSize(f, r.bufferSize)
	return nil
}

func (r *rotatingWriter) Write(data []byte) error {
	lineLen := int64(len(data) + 1) // data + newline
	if r.currentSize > 0 && (r.currentSize+lineLen) > r.maxSize {
		if err := r.rotate(); err != nil {
			return err
		}
	}

	if _, err := r.writer.Write(data); err != nil {
		return err
	}
	if err := r.writer.WriteByte('\n'); err != nil {
		return err
	}
	r.currentSize += lineLen
	return nil
}

func (r *rotatingWriter) rotate() error {
	if err := r.writer.Flush(); err != nil {
		return err
	}
	if err := r.file.Close(); err != nil {
		return err
	}

	currentPath := filepath.Join(r.dir, r.baseName)
	timestamp := time.Now().UnixNano()
	r.seq++
	rotatedPath := filepath.Join(r.dir, fmt.Sprintf("%s.%d.%d.jsonl", r.prefix, timestamp, r.seq))

	if err := os.Rename(currentPath, rotatedPath); err != nil {
		return fmt.Errorf("failed to rotate file %s: %w", currentPath, err)
	}

	if r.compress {
		r.wg.Add(1)
		go func(src string) {
			defer r.wg.Done()
			_ = compressFile(src)
		}(rotatedPath)
	}

	return r.openCurrent()
}

func compressFile(src string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	dest := src + ".gz"
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	gw := gzip.NewWriter(out)
	if _, err := io.Copy(gw, in); err != nil {
		_ = gw.Close()
		return err
	}
	if err := gw.Close(); err != nil {
		return err
	}

	// Close input file handle before deleting on Windows
	_ = in.Close()
	_ = os.Remove(src)
	return nil
}

func (r *rotatingWriter) Close() error {
	var firstErr error
	if r.writer != nil {
		if err := r.writer.Flush(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if r.file != nil {
		if err := r.file.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	r.wg.Wait()
	return firstErr
}

// FileSink manages asynchronous telemetry streams with batched file writes and rotation.
type FileSink struct {
	cfg          FileSinkConfig
	flowChan     chan FlowEvent
	alertChan    chan AlertEvent
	flowsWriter  *rotatingWriter
	alertsWriter *rotatingWriter
	stats        AtomicStats
	workersWg    sync.WaitGroup
	closed       uint32
}

// NewFileSink constructs and starts a new asynchronous FileSink.
func NewFileSink(cfg FileSinkConfig) (*FileSink, error) {
	if cfg.MaxSizeBytes <= 0 {
		cfg.MaxSizeBytes = DefaultMaxSizeBytes
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = DefaultBufferSize
	}
	if cfg.QueueCapacity <= 0 {
		cfg.QueueCapacity = DefaultQueueSize
	}

	fw, err := newRotatingWriter(cfg.OutputDir, "flows", cfg.MaxSizeBytes, cfg.BufferSize, cfg.CompressOnRotate)
	if err != nil {
		return nil, err
	}

	aw, err := newRotatingWriter(cfg.OutputDir, "alerts", cfg.MaxSizeBytes, cfg.BufferSize, cfg.CompressOnRotate)
	if err != nil {
		_ = fw.Close()
		return nil, err
	}

	fs := &FileSink{
		cfg:          cfg,
		flowChan:     make(chan FlowEvent, cfg.QueueCapacity),
		alertChan:    make(chan AlertEvent, cfg.QueueCapacity),
		flowsWriter:  fw,
		alertsWriter: aw,
	}

	fs.workersWg.Add(2)
	go fs.flowWorker()
	go fs.alertWorker()

	return fs, nil
}

func (f *FileSink) flowWorker() {
	defer f.workersWg.Done()
	scratch := make([]byte, 0, 512)
	for event := range f.flowChan {
		scratch = event.AppendJSON(scratch[:0])
		_ = f.flowsWriter.Write(scratch)
	}
	_ = f.flowsWriter.Close()
}

func (f *FileSink) alertWorker() {
	defer f.workersWg.Done()
	scratch := make([]byte, 0, 512)
	for event := range f.alertChan {
		scratch = event.AppendJSON(scratch[:0])
		_ = f.alertsWriter.Write(scratch)
	}
	_ = f.alertsWriter.Close()
}

// EmitFlow queues a flow event without blocking the capture pipeline.
func (f *FileSink) EmitFlow(event FlowEvent) {
	if atomic.LoadUint32(&f.closed) == 1 {
		atomic.AddUint64(&f.stats.DroppedFlows, 1)
		return
	}
	select {
	case f.flowChan <- event:
		atomic.AddUint64(&f.stats.EmittedFlows, 1)
	default:
		atomic.AddUint64(&f.stats.DroppedFlows, 1)
	}
}

// EmitAlert queues a security alert event without blocking.
func (f *FileSink) EmitAlert(event AlertEvent) {
	if atomic.LoadUint32(&f.closed) == 1 {
		atomic.AddUint64(&f.stats.DroppedAlerts, 1)
		return
	}
	select {
	case f.alertChan <- event:
		atomic.AddUint64(&f.stats.EmittedAlerts, 1)
	default:
		atomic.AddUint64(&f.stats.DroppedAlerts, 1)
	}
}

// Stats returns thread-safe telemetry metrics.
func (f *FileSink) Stats() Stats {
	return f.stats.Snapshot()
}

// Close drains in-flight events, flushes buffers, and waits for background compression.
func (f *FileSink) Close() error {
	if !atomic.CompareAndSwapUint32(&f.closed, 0, 1) {
		return nil
	}
	close(f.flowChan)
	close(f.alertChan)
	f.workersWg.Wait()
	return nil
}
