package codec

import "github.com/gpicchiarelli/integris/internal/resource"

func admitRecordBytes(n uint64) error {
	lim := resource.Limits{
		MaxBytes:      MaxRecordBytes,
		MaxCount:      1,
		MaxNesting:    1,
		MaxQueueDepth: 1,
		MaxConcurrent: 1,
		MaxRetries:    1,
	}
	if err := lim.AdmitBytes(n); err != nil {
		return limit("record_length", err.Error())
	}
	return nil
}
