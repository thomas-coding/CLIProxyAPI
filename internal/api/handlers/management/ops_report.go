package management

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const defaultOpsReportDir = "/root/ops-monitor/reports/ops"

var (
	errOpsReportNotFound = errors.New("ops report not found")
	opsReportDatePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	opsReportNow         = func() time.Time { return time.Now() }
	opsReportLocation    = time.FixedZone("CST", 8*60*60)
)

type opsReportFiles struct {
	Date         string
	MarkdownPath string
	JSONPath     string
}

// GetOpsReport returns yesterday's ops report by default and falls back to the latest
// available dated report when yesterday's files have not been generated yet.
func (h *Handler) GetOpsReport(c *gin.Context) {
	requestedDate := strings.TrimSpace(c.Query("date"))
	source := "yesterday"
	explicitDate := requestedDate != ""

	if explicitDate {
		if !opsReportDatePattern.MatchString(requestedDate) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid date, expected YYYY-MM-DD"})
			return
		}
		source = "date"
	} else {
		requestedDate = opsReportNow().In(opsReportLocation).AddDate(0, 0, -1).Format("2006-01-02")
	}

	files, fallbackToLatest, err := h.resolveOpsReportFiles(requestedDate, explicitDate)
	if err != nil {
		switch {
		case errors.Is(err, errOpsReportNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "ops report not found"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to load ops report: %v", err)})
		}
		return
	}

	if fallbackToLatest {
		source = "latest_fallback"
	}

	report, markdown, err := loadOpsReportPayload(files)
	if err != nil {
		switch {
		case errors.Is(err, errOpsReportNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "ops report not found"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to read ops report: %v", err)})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"requested_date":     requestedDate,
		"resolved_date":      files.Date,
		"source":             source,
		"fallback_to_latest": fallbackToLatest,
		"markdown":           markdown,
		"report":             report,
	})
}

func (h *Handler) resolveOpsReportFiles(requestedDate string, explicitDate bool) (opsReportFiles, bool, error) {
	dir := h.opsReportDirectory()
	if strings.TrimSpace(dir) == "" {
		return opsReportFiles{}, false, fmt.Errorf("ops report directory not configured")
	}

	files, err := findOpsReportFiles(dir, requestedDate)
	if err != nil && !errors.Is(err, errOpsReportNotFound) {
		return opsReportFiles{}, false, err
	}
	if err == nil {
		return files, false, nil
	}
	if explicitDate {
		return opsReportFiles{}, false, errOpsReportNotFound
	}

	latestFiles, err := findLatestOpsReportFiles(dir)
	if err != nil {
		return opsReportFiles{}, false, err
	}
	return latestFiles, true, nil
}

func (h *Handler) opsReportDirectory() string {
	candidates := []string{
		strings.TrimSpace(os.Getenv("ARROUTE_OPS_REPORT_DIR")),
		strings.TrimSpace(os.Getenv("OPS_REPORT_DIR")),
		defaultOpsReportDir,
	}

	for _, dir := range candidates {
		if dir == "" {
			continue
		}
		if abs, err := filepath.Abs(dir); err == nil {
			return abs
		}
		return filepath.Clean(dir)
	}

	return ""
}

func findOpsReportFiles(dir string, date string) (opsReportFiles, error) {
	if !opsReportDatePattern.MatchString(date) {
		return opsReportFiles{}, fmt.Errorf("invalid report date: %s", date)
	}

	files := opsReportFiles{
		Date:         date,
		MarkdownPath: filepath.Join(dir, date+".md"),
		JSONPath:     filepath.Join(dir, date+".json"),
	}

	hasMarkdown, err := isRegularFile(files.MarkdownPath)
	if err != nil {
		return opsReportFiles{}, err
	}
	if !hasMarkdown {
		files.MarkdownPath = ""
	}

	hasJSON, err := isRegularFile(files.JSONPath)
	if err != nil {
		return opsReportFiles{}, err
	}
	if !hasJSON {
		files.JSONPath = ""
	}

	if files.MarkdownPath == "" && files.JSONPath == "" {
		return opsReportFiles{}, errOpsReportNotFound
	}

	return files, nil
}

func findLatestOpsReportFiles(dir string) (opsReportFiles, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return opsReportFiles{}, errOpsReportNotFound
		}
		return opsReportFiles{}, err
	}

	byDate := make(map[string]opsReportFiles)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".md" && ext != ".json" {
			continue
		}

		date := strings.TrimSuffix(name, ext)
		if !opsReportDatePattern.MatchString(date) {
			continue
		}

		record := byDate[date]
		record.Date = date
		switch ext {
		case ".md":
			record.MarkdownPath = filepath.Join(dir, name)
		case ".json":
			record.JSONPath = filepath.Join(dir, name)
		}
		byDate[date] = record
	}

	if len(byDate) == 0 {
		return opsReportFiles{}, errOpsReportNotFound
	}

	dates := make([]string, 0, len(byDate))
	for date := range byDate {
		dates = append(dates, date)
	}
	sort.Strings(dates)

	latest := byDate[dates[len(dates)-1]]
	if latest.MarkdownPath == "" && latest.JSONPath == "" {
		return opsReportFiles{}, errOpsReportNotFound
	}
	return latest, nil
}

func loadOpsReportPayload(files opsReportFiles) (any, string, error) {
	var (
		report   any
		markdown string
	)

	if files.JSONPath != "" {
		raw, err := os.ReadFile(files.JSONPath)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, "", errOpsReportNotFound
			}
			return nil, "", err
		}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &report); err != nil {
				return nil, "", fmt.Errorf("invalid report json: %w", err)
			}
		}
	}

	if files.MarkdownPath != "" {
		raw, err := os.ReadFile(files.MarkdownPath)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, "", errOpsReportNotFound
			}
			return nil, "", err
		}
		markdown = string(raw)
	}

	if report == nil && markdown == "" {
		return nil, "", errOpsReportNotFound
	}

	return report, markdown, nil
}

func isRegularFile(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return info.Mode().IsRegular(), nil
}
