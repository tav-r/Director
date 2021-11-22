package li.tavr.Director

import burp.*

import java.io.PrintWriter
import java.net.URL
import java.util
import java.util.stream.Collectors
import collection.JavaConverters.*
import scala.language.postfixOps
import helpers.redirectParams

def doPassiveParamsScan(helpers: IExtensionHelpers)(messageInfo: IHttpRequestResponse): java.util.List[IScanIssue] = {
  val req = helpers.analyzeRequest(messageInfo.getHttpService, messageInfo.getRequest)

  if !req.getMethod.eq("GET") then return null

  val potential_redirect_param: List[IParameter] = redirectParams(req.getParameters.asScala toList)

  potential_redirect_param match {
    case List() => return null
    case params: List[IParameter] => return List(new IScanIssue{
      override def getConfidence: String = "Tentative"
      override def getIssueBackground: String = "User-specified redirects may lead to insecure" +
        " redirects if not properly validated"
      override def getIssueType: Int = 0x00500100
      override def getHttpMessages: Array[IHttpRequestResponse] = Array(messageInfo)
      override def getHttpService: IHttpService = messageInfo.getHttpService
      override def getIssueName: String = "Potential user-specified Redirect"
      override def getIssueDetail: String = "The URL uses parameters that might specify a redirect location:<br><ul>"
        + params.map(p => s"<li>${p.getName}=${p.getValue}</li>").mkString + "</ul>"
      override def getRemediationDetail: String = null
      override def getSeverity: String = "Medium"
      override def getUrl: URL = req.getUrl
      override def getRemediationBackground: String = null
    }) asJava
  }

  null
}