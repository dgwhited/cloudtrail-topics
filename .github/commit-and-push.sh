#!/usr/bin/env bash

CHANGES=0

echo "Commit and Push"
echo "------------------"
echo "Current Hash: ${GITHUB_SHA}"

# Git creds
git config --global user.email "${EMAIL}"
git config --global user.name "${NAME}"

echo "git add -A cloudtrail-topics"
git add -A cloudtrail-html-topics
git add -A cloudtrail-topics.json

# Test if changes
git diff HEAD --quiet cloudtrail-topics.json || CHANGES=1
git diff HEAD --quiet cloudtrail-html-topics || CHANGES=1

# If changes are present
if [[ ${CHANGES} -eq 1 ]]; then

  # Add and commit


  git commit -m 'New Cloudtrail Topics Detected'
  
  # Create date var for release name
  TODAY="$(date +'%Y-%m-%d')"

  # Push tag
  echo "git push--set-upstream origin main"
  git push --set-upstream origin main

else
  echo "No changes detected"
fi
