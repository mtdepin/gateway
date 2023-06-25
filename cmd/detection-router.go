package cmd

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/klauspost/compress/gzhttp"
	"github.com/klauspost/compress/gzip"
)

func registerDetectionRouter(router *mux.Router) {

	detectionAPI := detectionAPIHandlers{}

	detectionRouter := router.PathPrefix(SlashSeparator).Subrouter()

	gz := func(h http.HandlerFunc) http.HandlerFunc {
		return h
	}

	wrapper, err := gzhttp.NewWrapper(gzhttp.MinSize(1000), gzhttp.CompressionLevel(gzip.BestSpeed))
	if err == nil {
		gz = func(h http.HandlerFunc) http.HandlerFunc {
			return wrapper(h).(http.HandlerFunc)
		}
	}

	detectionRouter.Methods(http.MethodGet).Path("/status").HandlerFunc(
		collectAPIStats("status", maxClients(gz(httpTraceAll(detectionAPI.StatusInfoHandler)))))
	detectionRouter.Methods(http.MethodGet).Path("/status/request").HandlerFunc(
		collectAPIStats("request", maxClients(gz(httpTraceAll(detectionAPI.RequestQueueInfoHandler)))))

}
