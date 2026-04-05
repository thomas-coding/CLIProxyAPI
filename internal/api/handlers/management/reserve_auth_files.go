package management

import (
	"io"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
)

type reserveRefreshRequest struct {
	Names []string `json:"names"`
}

func (h *Handler) ListReserveAuthFiles(c *gin.Context) {
	if h == nil || h.reservePool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "reserve pool unavailable"})
		return
	}
	auths, err := h.reservePool.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	files := make([]gin.H, 0, len(auths))
	for _, auth := range auths {
		if entry := h.buildAuthFileEntry(auth); entry != nil {
			files = append(files, entry)
		}
	}
	sort.Slice(files, func(i, j int) bool {
		nameI, _ := files[i]["name"].(string)
		nameJ, _ := files[j]["name"].(string)
		return strings.ToLower(nameI) < strings.ToLower(nameJ)
	})
	c.JSON(http.StatusOK, gin.H{"files": files})
}

func (h *Handler) DownloadReserveAuthFile(c *gin.Context) {
	if h == nil || h.reservePool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "reserve pool unavailable"})
		return
	}
	name := strings.TrimSpace(c.Query("name"))
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	data, err := h.reservePool.Download(name)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(strings.ToLower(err.Error()), "invalid file name") {
			status = http.StatusBadRequest
		} else if os.IsNotExist(err) || strings.Contains(strings.ToLower(err.Error()), "file not found") || strings.Contains(strings.ToLower(err.Error()), "cannot find") {
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.Header("Content-Disposition", `attachment; filename="`+name+`"`)
	c.Data(http.StatusOK, "application/json", data)
}

func (h *Handler) UploadReserveAuthFile(c *gin.Context) {
	if h == nil || h.reservePool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "reserve pool unavailable"})
		return
	}
	file, err := c.FormFile("file")
	if err != nil || file == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file is required"})
		return
	}
	opened, err := file.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to open upload file"})
		return
	}
	defer func() {
		_ = opened.Close()
	}()

	data, err := io.ReadAll(opened)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read upload file"})
		return
	}

	if err = h.reservePool.Upload(file.Filename, data); err != nil {
		status := http.StatusInternalServerError
		if isReserveUploadValidationError(err) {
			status = http.StatusBadRequest
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) RefreshReserveAuthFiles(c *gin.Context) {
	if h == nil || h.reservePool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "reserve pool unavailable"})
		return
	}
	var body reserveRefreshRequest
	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
			return
		}
	}
	results, err := h.reservePool.RefreshUsage(c.Request.Context(), body.Names)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"results": results})
}

func isReserveUploadValidationError(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(err.Error()))
	if lower == "" {
		return false
	}
	for _, marker := range []string{
		"invalid",
		"only accepts",
		"missing",
		"file must end",
		"auth file is empty",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
