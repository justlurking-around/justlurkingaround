'use strict';

/**
 * GitHub Blame — Who committed the secret?
 *
 * Uses GitHub's GraphQL blame API to get:
 *  - Commit SHA where the secret was introduced
 *  - Commit author name + email
 *  - Commit date
 *  - Commit message
 *
 * This is used in reports and disclosure emails.
 * Only called for VALID findings (not every finding — saves API quota).
 */

const { getClient } = require('../utils/github-client');
const logger = require('../utils/logger');

/**
 * Get blame info for a specific file line
 * @param {string} repoName  - owner/repo
 * @param {string} filePath  - path inside repo
 * @param {number} lineNumber
 * @returns {Promise<BlameInfo|null>}
 */
async function getBlame(repoName, filePath, lineNumber) {
  const client = getClient();
  const [owner, repo] = repoName.split('/');
  if (!owner || !repo) return null;

  // GitHub GraphQL blame API
  const query = `
    query blame($owner: String!, $repo: String!, $expr: String!) {
      repository(owner: $owner, name: $repo) {
        object(expression: $expr) {
          ... on Commit {
            blame(path: "${filePath.replace(/"/g, '\\"')}") {
              ranges {
                startingLine
                endingLine
                commit {
                  oid
                  message
                  committedDate
                  author {
                    name
                    email
                    user { login }
                  }
                }
              }
            }
          }
        }
      }
    }
  `;

  try {
    const resp = await client.post('/graphql', {
      query,
      variables: { owner, repo, expr: 'HEAD' }
    }, { baseURL: 'https://api.github.com' });

    const ranges = resp.data?.data?.repository?.object?.blame?.ranges || [];
    if (!ranges.length) return null;

    // Find the range that contains our line number
    const target = lineNumber || 1;
    const range = ranges.find(r => r.startingLine <= target && r.endingLine >= target)
                  || ranges[0];

    if (!range?.commit) return null;

    const commit = range.commit;
    return {
      sha:         commit.oid,
      shortSha:    commit.oid?.substring(0, 8),
      message:     (commit.message || '').split('\n')[0].substring(0, 200),
      date:        commit.committedDate,
      authorName:  commit.author?.name,
      authorEmail: commit.author?.email,
      authorLogin: commit.author?.user?.login,
      commitUrl:   `https://github.com/${repoName}/commit/${commit.oid}`,
      fileUrl:     `https://github.com/${repoName}/blob/${commit.oid}/${filePath}#L${target}`,
    };
  } catch (err) {
    logger.debug(`[Blame] ${repoName}/${filePath}: ${err.message}`);
    return null;
  }
}

module.exports = { getBlame };
