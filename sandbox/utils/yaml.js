/**
 * YAML Utility for PAVE Configuration Files
 * 
 * Provides simple YAML parsing and serialization for:
 * - ~/.pave/tokens.yaml
 * - ~/.pave/permissions.yaml
 */

const yaml = require('js-yaml');

/**
 * Parse a YAML string into a JavaScript object
 * @param {string} content - YAML content to parse
 * @returns {object} Parsed object
 */
function parseYaml(content) {
  return yaml.load(content);
}

/**
 * Serialize a JavaScript object to YAML string
 * @param {object} obj - Object to serialize
 * @param {object} options - Serialization options
 * @returns {string} YAML string
 */
function stringifyYaml(obj, options = {}) {
  return yaml.dump(obj, {
    indent: 2,
    lineWidth: 120,
    noRefs: true,
    sortKeys: false,
    ...options
  });
}

/**
 * Add a header comment to YAML content
 * @param {string} yamlContent - YAML string
 * @param {string} header - Comment header (without # prefix)
 * @returns {string} YAML with header comment
 */
function addYamlHeader(yamlContent, header) {
  const lines = header.split('\n').map(line => `# ${line}`);
  return lines.join('\n') + '\n\n' + yamlContent;
}

module.exports = {
  parseYaml,
  stringifyYaml,
  addYamlHeader
};
