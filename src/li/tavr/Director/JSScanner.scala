package li.tavr.Director

import burp.*

import java.io.PrintWriter
import java.net.URL
import java.util
import java.util.stream.Collectors
import collection.JavaConverters.*
import scala.language.postfixOps
import helpers.javaScriptPatterns

def doPassiveJSScan(helpers: IExtensionHelpers)(messageInfo: IHttpRequestResponse): java.util.List[IScanIssue] = {
  val res = helpers analyzeResponse(messageInfo getResponse)

  if !res.getInferredMimeType.eq("script") then return null

  val potential_dom_redirect: List[String] = javaScriptPatterns(String(messageInfo getResponse))

  potential_dom_redirect match {
    case List() => return null
    case matches: List[String] => return List(new IScanIssue{
      override def getConfidence: String = "Tentative"
      override def getIssueBackground: String = "DOM based redirects that interpret user supplied data may" +
        " result in insecure redirects or XSS vulnerabilities"
      override def getIssueType: Int = 0x00500100
      override def getHttpMessages: Array[IHttpRequestResponse] = Array(messageInfo)
      override def getHttpService: IHttpService = messageInfo.getHttpService
      override def getIssueName: String = "DOM-based Redirect"
      override def getIssueDetail: String = "The script performs a DOM-based redirect location:<br><ul>"
        + matches.map(m => s"<li>${m}</li>").mkString + "</ul>"
      override def getRemediationDetail: String = null
      override def getSeverity: String = "Low"
      override def getUrl: URL = helpers analyzeRequest(messageInfo.getHttpService, messageInfo.getRequest) getUrl
      override def getRemediationBackground: String = null
    }) asJava
  }

  null
}
