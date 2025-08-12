usage() {
    echo "Usage: $0 --token TOKEN --pat GHCR_PAT_TOKEN"
    exit 1
}

if [ -n "$GITHUB_SHA" ]; then
    COMMIT_SHA="$GITHUB_SHA"
elif [ -n "$CI_COMMIT_SHA" ]; then
    COMMIT_SHA="$CI_COMMIT_SHA"
else
    COMMIT_SHA=""
fi

if [ -n "$GITHUB_ACTOR" ]; then
    COMMIT_AUTHOR="$GITHUB_ACTOR"
elif [ -n "$GITLAB_USER_NAME" ]; then
    COMMIT_AUTHOR="$GITLAB_USER_NAME"
else
    COMMIT_AUTHOR=""
fi

if [ -n "$GITHUB_REPOSITORY" ]; then
    REPO_NAME="$GITHUB_REPOSITORY"
elif [ -n "$CI_PROJECT_PATH" ]; then
    REPO_NAME="$CI_PROJECT_PATH"
else
    print_message "[!]" "Repository empty" "Repository name is empty"
    exit 1
fi

TOKEN=""
GHCR_PAT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --token)
            TOKEN="$2"
            shift 2
            ;;
        --pat)
            GHCR_PAT="$2"
            shift 2
            ;;
        *)
    esac
done

if [ -z "$TOKEN" ]; then
    print_message "[!]" "Missing flag" "--token is required"
    usage
fi