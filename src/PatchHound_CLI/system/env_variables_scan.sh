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
    SCAN_PROFILE_CONFIG_FILE="$SCRIPT_DIR/scan_profile.config"
    REPO_NAME=$(grep "^REPO_NAME=" "$SCAN_PROFILE_CONFIG_FILE" | cut -d= -f2-)
    if [ -z "$REPO_NAME" ]; then
      print_message "[!]" "Missing config" "REPO_NAME is missing"
      exit 1
    fi
fi

if [[ -n "$IMAGE" ]]; then
    TARGET="$IMAGE"
fi

if [[ "$TARGET" == "." ]]; then
  DOCKER_REGISTRY=""
elif [[ "$TARGET" != *"/"* ]]; then
  DOCKER_REGISTRY=""
else
  FIRST_SEGMENT="$(echo "$TARGET" | cut -d/ -f1)"
  if [[ "$FIRST_SEGMENT" == *.* ]]; then
    DOCKER_REGISTRY="$FIRST_SEGMENT"
  else
    DOCKER_REGISTRY="docker.io"
  fi
fi

if [ -n "$PAT_TOKEN" ] && [ -n "$DOCKER_REGISTRY" ]; then
  if echo "$PAT_TOKEN" | docker login "$DOCKER_REGISTRY" -u "$GITHUB_ACTOR" --password-stdin; then
    print_message "[+]" "Docker login succeeded" "Authenticated to $DOCKER_REGISTRY"
  else
    print_message "[!]" "Docker login failed" "Could not login to $DOCKER_REGISTRY using the provided PAT"
    exit 1
  fi
else
  if [ -z "$DOCKER_REGISTRY" ]; then
    print_message "[~]" "No registry detected" "Skipping Docker auth for local or directory target."
  elif [ -z "$PAT_TOKEN" ]; then
    print_message "[~]" "PAT_TOKEN not set" "PAT_TOKEN not set. Skipping Docker auth."
  fi
fi