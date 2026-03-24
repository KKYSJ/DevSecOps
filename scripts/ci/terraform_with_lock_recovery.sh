#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <log-path> <terraform> [args...]" >&2
  exit 2
fi

LOG_PATH="$1"
shift
CMD=( "$@" )

LOCK_RETRY_ATTEMPTS="${TF_LOCK_RETRY_ATTEMPTS:-10}"
LOCK_RETRY_SLEEP_SECONDS="${TF_LOCK_RETRY_SLEEP_SECONDS:-30}"
LOCK_STALE_MINUTES="${TF_LOCK_STALE_MINUTES:-45}"

mkdir -p "$(dirname "${LOG_PATH}")"
: > "${LOG_PATH}"

LAST_OUTPUT_FILE=""
LAST_STATUS=0

cleanup() {
  if [ -n "${LAST_OUTPUT_FILE}" ] && [ -f "${LAST_OUTPUT_FILE}" ]; then
    rm -f "${LAST_OUTPUT_FILE}"
  fi
}

trap cleanup EXIT

run_command() {
  LAST_OUTPUT_FILE="$(mktemp)"

  set +e
  "${CMD[@]}" 2>&1 | tee -a "${LOG_PATH}" | tee "${LAST_OUTPUT_FILE}"
  LAST_STATUS="${PIPESTATUS[0]}"
  set -e

  return "${LAST_STATUS}"
}

extract_lock_value() {
  local field="$1"
  sed -n "s/^  ${field}:[[:space:]]*//p" "${LAST_OUTPUT_FILE}" | head -n 1
}

lock_error_detected() {
  grep -q "Error acquiring the state lock" "${LAST_OUTPUT_FILE}"
}

lock_age_minutes() {
  local created_at="$1"
  local created_epoch
  local now_epoch

  created_epoch="$(date -u -d "${created_at}" +%s 2>/dev/null || true)"
  if [ -z "${created_epoch}" ]; then
    return 1
  fi

  now_epoch="$(date -u +%s)"
  if [ "${now_epoch}" -lt "${created_epoch}" ]; then
    return 1
  fi

  echo $(( (now_epoch - created_epoch) / 60 ))
}

unlock_performed="false"

for attempt in $(seq 1 "${LOCK_RETRY_ATTEMPTS}"); do
  echo "==> Terraform command attempt ${attempt}/${LOCK_RETRY_ATTEMPTS}" | tee -a "${LOG_PATH}"

  if run_command; then
    exit 0
  fi

  if ! lock_error_detected; then
    exit "${LAST_STATUS}"
  fi

  lock_id="$(extract_lock_value "ID")"
  lock_path="$(extract_lock_value "Path")"
  lock_operation="$(extract_lock_value "Operation")"
  lock_who="$(extract_lock_value "Who")"
  lock_created="$(extract_lock_value "Created")"

  {
    echo "Terraform state lock detected."
    echo "  Lock ID: ${lock_id:-unknown}"
    echo "  Lock path: ${lock_path:-unknown}"
    echo "  Lock operation: ${lock_operation:-unknown}"
    echo "  Lock owner: ${lock_who:-unknown}"
    echo "  Lock created: ${lock_created:-unknown}"
  } | tee -a "${LOG_PATH}"

  lock_age=""
  if [ -n "${lock_created}" ]; then
    lock_age="$(lock_age_minutes "${lock_created}" || true)"
  fi

  if [ -n "${lock_age}" ]; then
    echo "  Lock age: ${lock_age} minute(s)" | tee -a "${LOG_PATH}"
  fi

  if [ "${unlock_performed}" != "true" ] && [ -n "${lock_id}" ] && [ -n "${lock_age}" ] && [ "${lock_age}" -ge "${LOCK_STALE_MINUTES}" ]; then
    {
      echo "Lock is older than ${LOCK_STALE_MINUTES} minute(s)."
      echo "Attempting terraform force-unlock for stale lock ${lock_id}."
    } | tee -a "${LOG_PATH}"

    set +e
    terraform force-unlock -force "${lock_id}" 2>&1 | tee -a "${LOG_PATH}"
    unlock_status="${PIPESTATUS[0]}"
    set -e

    if [ "${unlock_status}" -ne 0 ]; then
      echo "terraform force-unlock failed." | tee -a "${LOG_PATH}"
      exit "${LAST_STATUS}"
    fi

    unlock_performed="true"
    sleep 5
    continue
  fi

  if [ "${attempt}" -eq "${LOCK_RETRY_ATTEMPTS}" ]; then
    {
      echo "Terraform state lock did not clear after ${LOCK_RETRY_ATTEMPTS} attempt(s)."
      echo "Automatic unlock is only performed for locks older than ${LOCK_STALE_MINUTES} minute(s)."
    } | tee -a "${LOG_PATH}"
    exit "${LAST_STATUS}"
  fi

  echo "Waiting ${LOCK_RETRY_SLEEP_SECONDS} second(s) before retrying..." | tee -a "${LOG_PATH}"
  sleep "${LOCK_RETRY_SLEEP_SECONDS}"
done

exit "${LAST_STATUS}"
