// http4k's MCP SDK by shape: a capability is BOUND with the same infix
// `bind` the router uses, and is not an HTTP route.
package org.http4k.ai.mcp

class Tool(val name: String)
class ToolResponse(val text: String)
infix fun Tool.bind(handler: (String) -> ToolResponse): Pair<Tool, (String) -> ToolResponse> = this to handler
