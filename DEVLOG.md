# Dev Log & Notes

## Git Feature Trees

```bash
# start from main (or whatever your trunk branch is)
git checkout main
git pull origin main        # ensure it’s up‑to‑date

# create a new feature branch
git checkout -b feature/your-description

# work, add & commit as you go
git add path/to/file
git commit -m "feat: add …"

# push branch to remote for review
git push -u origin feature/your-description

# later, bring in updates from main
git checkout main
git pull origin main
git checkout feature/your-description
git merge main              # or rebase main

# resolve any conflicts, then:
git push                    # update remote branch

# when ready to merge
# create a pull request on GitHub, or from cli:
gh pr create --base main --head feature/your-description \
  --title "feature: …" --body "…"

# after PR is merged, cleanup
git checkout main
git pull origin main
git branch -d feature/your-description        # local
git push origin --delete feature/your-description  # remote
```