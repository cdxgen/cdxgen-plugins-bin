// HttpClient 5 moved the whole tree from org.apache.http to org.apache.hc
// (verified against httpclient5 5.3.1); the constructor sink's generation
// twin, modelled since and pinned here.
package org.apache.hc.client5.http.classic.methods

class HttpGet(val uri: String)
