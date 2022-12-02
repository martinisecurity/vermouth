package vermouth

import (
	"context"
	"github.com/ipifony/vermouth/logger"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	InsertSigningSql      = "INSERT INTO signing_record (src_tn, dst_tn, attestation, orig_id) VALUES ($1,$2,$3,$4)"
	InsertVerificationSql = "INSERT INTO verification_record (sip_from, sip_pai, sip_to, sip_ruri, identity, x5u_url, " +
		"cert_chain_raw, status_no_signature, status_bad_format, status_not_trusted, status_invalid_signature, " +
		"status_tn_mismatch, status_stale, status_valid, attestation, orig_ocn) " +
		"VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)"
)

var pool *pgxpool.Pool

func ClosePool() {
	if pool != nil {
		pool.Close()
	}
}

func InitPool() error {
	if !GlobalConfig.isDbEnabled() {
		return nil
	}
	var dbErr error
	config, dbErr := pgxpool.ParseConfig(GlobalConfig.PrepareDbUrl() + "?pool_max_conns=5&pool_min_conns=2")
	if dbErr != nil {
		return dbErr
	}
	pool, dbErr = pgxpool.NewWithConfig(context.Background(), config)
	if dbErr != nil {
		pool = nil
		return dbErr
	}
	dbErr = pool.Ping(context.Background())
	if dbErr != nil {
		pool = nil
		return dbErr
	}
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "DB Logging Active"}
	return nil
}

func WriteSigningRecord(srcTn *string, dstTn *string, attestation *string, origId *string) {
	if pool == nil {
		return
	}
	dbConn, err := pool.Acquire(context.Background())
	if err != nil || dbConn == nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "Unable to get a db connection. Error: " + err.Error()}
		return
	}
	defer dbConn.Release()
	ret, err := dbConn.Query(context.Background(), InsertSigningSql, srcTn, dstTn, attestation, origId)
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "Error inserting into signing_record. Error: " + err.Error()}
		return
	}
	ret.Close()
}

func WriteVerificationRecord(record *VerificationRecord) {
	if pool == nil {
		return
	}
	dbConn, err := pool.Acquire(context.Background())
	if err != nil || dbConn == nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "Unable to get a db connection. Error: " + err.Error()}
		return
	}
	defer dbConn.Release()
	var certChain string
	if record.CertBytes != nil {
		certChain = string(*record.CertBytes)
	}

	ret, err := dbConn.Query(context.Background(), InsertVerificationSql,
		record.From,
		record.Pai,
		record.To,
		record.Ruri,
		record.Identity,
		record.X5U,
		certChain,
		boolToInt(record.StatusNoSignature),
		boolToInt(record.StatusBadFormat),
		boolToInt(record.StatusNotTrusted),
		boolToInt(record.StatusInvalidSignature),
		boolToInt(record.StatusTnMismatch),
		boolToInt(record.StatusStale),
		boolToInt(record.StatusValid),
		record.Attestation,
		record.OrigOcn)
	if err != nil {
		logger.LogChan <- &logger.LogMessage{Severity: logger.ERROR, MsgStr: "Error inserting into verification_record. Error: " + err.Error()}
		return
	}
	ret.Close()
}

func boolToInt(val bool) int8 {
	if val {
		return 1
	}
	return 0
}
