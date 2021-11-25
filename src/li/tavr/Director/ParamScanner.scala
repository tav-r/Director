package li.tavr.Director

import burp.*

import java.io.PrintWriter
import java.net.URL
import java.util
import java.util.stream.Collectors
import collection.JavaConverters.*
import scala.language.postfixOps
import helpers.redirectParams

def findParams(helpers: IExtensionHelpers)(reqs: List[IHttpRequestResponse], url: String): Option[IHttpRequestResponse] = {
  reqs match {
    case List() => None
    case r::rs => if !helpers.analyzeRequest(r)
      .getParameters.asScala.filter(q => url.contains(q.getValue)).isEmpty then {
      Some(r)
    } else {
      findParams(helpers)(rs, url)
    }
  }
}

def doPassiveParamsScan(callbacks: IBurpExtenderCallbacks)
                       (messageInfo: IHttpRequestResponse): java.util.List[IScanIssue] = {
  val helpers = callbacks.getHelpers()

  val req = helpers.analyzeRequest(messageInfo getHttpService, messageInfo getRequest)
  val res = helpers.analyzeResponse(messageInfo getResponse)

  val location_headers = res.getHeaders.asScala.filter(h => h.toLowerCase.startsWith("location"))

  if !req.getMethod.eq("GET") || location_headers.isEmpty then {
    return null
  }

  findParams(helpers)(
    callbacks.getProxyHistory.reverse
    .toList.filter(r => helpers.analyzeRequest(r).getMethod eq "GET" )
    .take(20),
    location_headers.head.split(":").toList.last.trim
  ) match {
    case None => null
    case Some(r) => return List(new IScanIssue{
      override def getConfidence: String = "Tentative"
      override def getIssueBackground: String = "User-specified redirects may lead to insecure" +
      " redirects if not properly validated"
      override def getIssueType: Int = 0x00500100
      override def getHttpMessages: Array[IHttpRequestResponse] = Array(r)
      override def getHttpService: IHttpService = messageInfo.getHttpService
      override def getIssueName: String = "User-specified Redirect"
      override def getIssueDetail: String = "The URL uses parameters that seem to specify a redirect location:<br><ul>"
      + s"<li>${helpers.analyzeRequest(r).getUrl.toString}</li></ul>"
      override def getRemediationDetail: String = null
      override def getSeverity: String = "Medium"
      override def getUrl: URL = req.getUrl
      override def getRemediationBackground: String = null
      }) asJava
  }

  null
}
