package main

// Default exporters written by "yars init" into .yars/exporters/.
var exampleExporters = map[string]string{
	"docx.yaml": `# Client report as Word document, generated with pandoc.
# Optional: put a styled reference document next to this file and set
#   template: reference.docx
name: Client report (DOCX)
type: pandoc
format: docx
args: [--toc]
statuses: [complete]
# true: making the file marks its findings reported
mark_reported: false
`,
	"confluence.yaml": `# HTML for pasting into Confluence. To publish directly instead, add:
#   confluence:
#       base_url: https://your-site.atlassian.net/wiki
#       space: SEC
#       parent_id: "123456"
#       user_env: CONFLUENCE_USER     # env vars on the YARS server
#       token_env: CONFLUENCE_TOKEN
# The account needs permission to add pages and to add and delete attachments in the space.
# Without mark_reported, the HTML file marks nothing and a published page
# marks its findings reported; mark_reported: true or false sets it.
name: Confluence HTML
type: confluence
statuses: [complete]
`,
}
