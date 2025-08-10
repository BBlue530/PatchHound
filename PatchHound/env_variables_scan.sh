usage() {
    echo "Usage: $0 --token TOKEN --pat GHCR_PAT_TOKEN"
    exit 1
}

TOKEN=""
PAT_TOKEN=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --token)
            TOKEN="$2"
            shift 2
            ;;
        --pat)
            PAT_TOKEN="$2"
            shift 2
            ;;
        *)
    esac
done

if [ -z "$TOKEN" ]; then
    echo "Error: --token are required"
    usage
fi