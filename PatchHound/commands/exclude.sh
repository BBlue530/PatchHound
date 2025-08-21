SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
BASE_DIR="$( dirname "$SCRIPT_DIR" )"
CONFIG_FILE="$SCRIPT_DIR/../scan.config"
source "$BASE_DIR/system/config.sh"
source "$BASE_DIR/system/env_system.sh"

EXCLUDE_PATH="./$EXCLUDE_FILE"
CVE=""
COMMENT=""

ensure_exclude_path() {
    if [[ ! -f "$EXCLUDE_PATH" ]]; then
        echo '{"exclusions":[]}' > "$EXCLUDE_PATH"
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --list)
            ensure_exclude_path
            cat "$EXCLUDE_PATH"
            exit 0
            ;;
        --remove)
            CVE_TO_REMOVE="$2"
            if [[ -z "$CVE_TO_REMOVE" ]]; then
                print_message "[!]" "Missing flag" ""
                usage_exclude
            fi
            shift 2
            ensure_exclude_path
            if jq -e --arg cve "$CVE_TO_REMOVE" '.exclusions[] | select(.vulnerability==$cve)' "$EXCLUDE_PATH" >/dev/null; then
                jq --arg cve "$CVE_TO_REMOVE" 'del(.exclusions[] | select(.vulnerability==$cve))' \
                    "$EXCLUDE_PATH" > "${EXCLUDE_PATH}.tmp" && mv "${EXCLUDE_PATH}.tmp" "$EXCLUDE_PATH"
                print_message "[i]" "Exclusion removed" "Removed $CVE_TO_REMOVE from exclusions"
            else
                print_message "[!]" "Exclusion status" "CVE $CVE_TO_REMOVE not found in exclusions"
            fi
            exit 0
            ;;
        --cve)
            CVE="$2"
            shift 2
            ;;
        --comment)
            shift
            COMMENT=""
            while [[ $# -gt 0 ]] && [[ "$1" != --* ]]; do
                COMMENT="$COMMENT $1"
                shift
            done
            COMMENT="${COMMENT#"${COMMENT%%[![:space:]]*}"}"
            ;;
        --help)
            usage_exclude
            exit 1
            ;;
        *)
            shift
            ;;
    esac
done

if [[ -z "$CVE" || -z "$COMMENT" ]]; then
    print_message "[!]" "Missing flag" "Usage: $0 exclude --cve <CVE-ID> --comment <text>"
    usage_exclude
fi

ensure_exclude_path

if jq -e --arg cve "$CVE" '.exclusions[] | select(.vulnerability==$cve)' "$EXCLUDE_PATH" >/dev/null; then
    print_message "[i]" "Exclusion status" "CVE $CVE already exists in exclusions"
    exit 0
fi

jq --arg cve "$CVE" --arg comment "$COMMENT" \
   '.exclusions += [{"vulnerability": $cve, "comment": $comment}]' \
   "$EXCLUDE_PATH" > "${EXCLUDE_PATH}.tmp" && mv "${EXCLUDE_PATH}.tmp" "$EXCLUDE_PATH"

print_message "[i]" "Exclusion added" "Added CVE $CVE to $EXCLUDE_PATH"