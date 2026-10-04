#!/bin/sh
#
# Create an annotated tag on the release branch whose message lists the
# commits since the previous tag, newest first. Shows a preview and asks
# before doing anything. The tag is created locally only; push it
# afterwards.
#
# usage: hack/create-tag.sh <tag>

set -eu

branch=main

die()
{
    echo "create-tag: $*" >&2
    exit 1
}

[ $# -eq 1 ] || die "usage: $0 <tag>"
tag=$1

git rev-parse --git-dir >/dev/null 2>&1 || die "not inside a git repository"
git rev-parse --verify --quiet "refs/heads/$branch" >/dev/null ||
    die "there is no $branch branch"
git check-ref-format "refs/tags/$tag" || die "invalid tag name: $tag"
! git rev-parse --verify --quiet "refs/tags/$tag" >/dev/null ||
    die "tag $tag already exists"

# Nearest tag reachable from the branch; absent on a repo that was never
# tagged, in which case every commit on the branch goes into the list.
last=$(git describe --tags --abbrev=0 "$branch" 2>/dev/null || true)
range=${last:+$last..}$branch

# Merge commits carry no change of their own, only noise for a changelog.
commits=$(git log --no-merges --format='  + %as :: %h :: %s' "$range")
[ -n "$commits" ] ||
    die "no commits on $branch since ${last:-the first commit}"

msgfile=$(mktemp)
trap 'rm -f "$msgfile"' EXIT
{
    echo "$tag"
    echo
    echo "This tag includes the following changes:"
    echo
    echo "$commits"
    echo
    echo "** That's all, see you on next tag **"
} > "$msgfile"

echo "Tag:     $tag"
echo "Target:  $branch @ $(git rev-parse --short "$branch")"
echo "Since:   ${last:-(no previous tag)}"
if git rev-parse --verify --quiet "refs/remotes/origin/$branch" >/dev/null &&
   [ "$(git rev-parse "$branch")" != "$(git rev-parse "origin/$branch")" ]; then
    echo "Warning: local $branch differs from origin/$branch"
fi
echo
echo "Message:"
echo "--------"
cat "$msgfile"
echo "--------"
echo
printf 'Create tag %s? [y/N] ' "$tag"
read -r answer || answer=
case $answer in
y|Y|yes|YES)
    ;;
*)
    echo "aborted, nothing created"
    exit 1
    ;;
esac

git tag -a "$tag" -F "$msgfile" "$branch"
echo "created tag $tag; push it with: git push origin $tag"
