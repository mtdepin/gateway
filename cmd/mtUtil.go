package cmd

import (
	"context"
)

//通过context传递的租户Id字段
const Ctx_Host = "Host"
const Ctx_Auth = "Auth"
const Ctx_TenantId = "TenantId"
const Ctx_ParentUserId = "ParentUserId"
const Ctx_Cred = "Cred"
const Ctx_UserQuota = "UserQuota"
const Ctx_SystemId = 0x7fffffff

const (
	DEFAULT_USER_QUOTA = 20
)

func JudgeUserID(ctx context.Context) (int, bool) {
	ai := globalIAMSys.GetAuthInfo(ctx)
	if ai == nil || ai.TenantId == 0 {
		return 0, false
	}
	return ai.TenantId, true
	//c := ctx.Value(Ctx_TenantId)
	//value := reflect.ValueOf(c)
	//if value.IsValid() {
	//	if value.IsZero() {
	//		return 0, false
	//	}
	//
	//	na, ok := c.(int)
	//	if ok {
	//		return na, ok
	//	} else {
	//		if na, ok := c.(float64); ok {
	//			return int(na), ok
	//		}
	//	}
	//}
	//return 0, false
}
