package cmd

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/minio/minio/internal/logger"
)

func (api objectAPIHandlers) GetDagTreeHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "GetDagTreeHandler")
	defer logger.AuditLog(ctx, w, r)
	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponseHeadersOnly(w, errorCodes.ToAPIErr(ErrServerNotInitialized))
		return
	}
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object := vars["object"]
	cid := r.FormValue("cid")
	opts, err := getOpts(ctx, r, bucket, object)
	if err != nil {
		writeErrorResponseHeadersOnly(w, errorCodes.ToAPIErr(ErrServerNotInitialized))
		return
	}

	res, err := objectAPI.GetDagTree(ctx, bucket, object, cid, opts)
	if err := checkoutTenantId(ctx, objectAPI, bucket, nil); err != nil {
		if err != nil {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
			return
		}
	}
	if err != nil {
		writeErrorResponseHeadersOnly(w, toAPIError(ctx, err))
		return
	}

	writeSuccessResponseJSON(w, res)
	return
}
