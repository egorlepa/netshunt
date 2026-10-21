package platform

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

const (
	logFileMaxSize   = 10 << 20 // rotate when the active file would exceed this
	logFileKeep      = 4        // rotated files kept: netshunt.log.1 .. netshunt.log.4
	logQueueCap      = 4096
	logFlushInterval = 2 * time.Second
)

// FileLog is an asynchronous, size-rotated log file. Write never touches the
// disk: lines go through a bounded queue to a writer goroutine that buffers
// them and flushes periodically, so a slow USB stick cannot stall the caller.
// When the queue is full, lines are dropped and the count is logged later.
type FileLog struct {
	path    string
	maxSize int64
	keep    int

	mu      sync.RWMutex // guards closed against sends racing Close
	closed  bool
	lines   chan []byte
	dropped atomic.Int64
	done    chan struct{}

	f    *os.File
	w    *bufio.Writer
	size int64
}

// OpenFileLog creates the log directory and starts the writer goroutine.
func OpenFileLog(path string) (*FileLog, error) {
	return openFileLog(path, logFileMaxSize, logFileKeep)
}

func openFileLog(path string, maxSize int64, keep int) (*FileLog, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	l := &FileLog{
		path:    path,
		maxSize: maxSize,
		keep:    keep,
		lines:   make(chan []byte, logQueueCap),
		done:    make(chan struct{}),
	}
	if err := l.open(); err != nil {
		return nil, err
	}
	go l.loop()
	return l, nil
}

// Write enqueues one log line without blocking. slog handlers call it once
// per record with the full line, and p is reused afterwards, so it is copied.
func (l *FileLog) Write(p []byte) (int, error) {
	line := make([]byte, len(p))
	copy(line, p)
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		return len(p), nil
	}
	select {
	case l.lines <- line:
	default:
		l.dropped.Add(1)
	}
	return len(p), nil
}

// Close drains the queue, flushes and closes the file. Later writes are
// discarded.
func (l *FileLog) Close() {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	close(l.lines)
	l.mu.Unlock()
	<-l.done
}

func (l *FileLog) loop() {
	defer close(l.done)
	ticker := time.NewTicker(logFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case line, ok := <-l.lines:
			if !ok {
				l.write(nil)
				l.closeFile()
				return
			}
			l.write(line)
		case <-ticker.C:
			l.flush()
		}
	}
}

// write reports dropped lines first, then appends line (if any), rotating
// before the active file would exceed maxSize. Errors are ignored: there is
// nowhere left to log them.
func (l *FileLog) write(line []byte) {
	if n := l.dropped.Swap(0); n > 0 {
		l.append([]byte(fmt.Sprintf("time=%s level=WARN msg=\"log queue full, lines dropped\" dropped=%d\n",
			time.Now().Format(time.RFC3339Nano), n)))
	}
	if line != nil {
		l.append(line)
	}
}

func (l *FileLog) append(line []byte) {
	if l.f != nil && l.size > 0 && l.size+int64(len(line)) > l.maxSize {
		l.rotate()
	}
	// A failed reopen after rotation (e.g. the stick went away) drops lines
	// and is retried on the next one.
	if l.f == nil && l.open() != nil {
		return
	}
	n, _ := l.w.Write(line)
	l.size += int64(n)
}

func (l *FileLog) rotate() {
	l.closeFile()
	for i := l.keep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", l.path, i), fmt.Sprintf("%s.%d", l.path, i+1))
	}
	_ = os.Rename(l.path, l.path+".1")
}

func (l *FileLog) flush() {
	if l.f != nil {
		_ = l.w.Flush()
	}
}

func (l *FileLog) closeFile() {
	if l.f != nil {
		_ = l.w.Flush()
		_ = l.f.Close()
		l.f, l.w = nil, nil
	}
}

func (l *FileLog) open() error {
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	l.f = f
	l.w = bufio.NewWriterSize(f, 64<<10)
	l.size = st.Size()
	return nil
}
