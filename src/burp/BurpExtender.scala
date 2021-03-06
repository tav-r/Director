package burp

import burp.{IBurpExtender, IBurpExtenderCallbacks, IExtensionHelpers}
import li.tavr.Director.{doPassiveParamsScan,doPassiveJSScan}

import java.io.PrintWriter
import java.util

class BurpExtender extends IBurpExtender {

  override def registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks): Unit = {
    callbacks.setExtensionName("Director")

    // register parameter scanner
    callbacks.registerScannerCheck(new IScannerCheck {
      override def doPassiveScan(baseRequestResponse: IHttpRequestResponse): util.List[IScanIssue]
        = doPassiveParamsScan(callbacks)(baseRequestResponse)
      override def doActiveScan(baseRequestResponse: IHttpRequestResponse,
                                insertionPoint: IScannerInsertionPoint
                               ): util.List[IScanIssue] = null
      override def consolidateDuplicateIssues(existingIssue: IScanIssue, newIssue: IScanIssue): Int = 0
    })

    // register JavaScript scanner
    callbacks.registerScannerCheck(new IScannerCheck {
      override def doPassiveScan(baseRequestResponse: IHttpRequestResponse): util.List[IScanIssue]
        = doPassiveJSScan(callbacks.getHelpers)(baseRequestResponse)
      override def doActiveScan(baseRequestResponse: IHttpRequestResponse,
                                insertionPoint: IScannerInsertionPoint
                               ): util.List[IScanIssue] = null
      override def consolidateDuplicateIssues(existingIssue: IScanIssue, newIssue: IScanIssue): Int = 0
    })

    PrintWriter(callbacks.getStdout(), true).println(
     """@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@w@@@@@@@@@@@@@@@@@@@@@@@
       |@@@@@@@@@@B@@@@@@@@@@@@@@@@@@@@;@@@@@@@@@@@@@@@@@@@@@@@
       |@@@@@@@@@N3@@@@@@@@@@@@@@@@@@@@'Q@@@@@@@@@@@@@@@@@@@@@@
       |@@@@@@@@@V=@@@@@@@@Qa@@@@@@@@@B`E@@@@@@@@@@@@@@@@@B@@@@
       |@@@@@@@@@k D@@@@@@@@~B@@@@@@@@B-N@@@@@@E@@@@@@@@@@?@@@@
       |@@@@@@@@d: A@@@@@@@; @@@@@@@@@@'Q@@@@@@v@@@@@@@@@B'@@@@
       |@@@@@@@@B  B@@@@@@@w N@@@@@@@@@"|@54@@Nj@@@@@@@@@@;=6j@
       |@@@@@@@@@''@@@@@@@@@:'N@@@@@@@@; N>|@@d!@@@@@@@@@@B` v@
       |@N517a&B@:-@@@@@@@@@O '@@@@@@@@L %N u@D u@@@@@@@@@@u ,@
       |@@@@@k|''  cg@@@@@@@B  q@@@@@@@N::5 vBB`-@@@@@@@@@@B` N
       |@@@@@@@@:; -'-/B@@@d: '@@@@@@@@@@: ,@aT: n@@@@@@@@@| a@
       |@@@@@@@4O; g@@7`;4B@: !@@@@@@@@@y' m@@@_ `@@@@@@@@K v@@
       |@@@@@@@@v  B@@@kV` `: :@@@@@@@@@@; "D@@q  +@@@@@@K-`B@@
       |@@@@@@@@B` A@@@@i  `| -@@@@@@@@@@N  D@@@k  A@@@d' ;`N@@
       |@@@@@@@@@, i@BC- .s+@; B@@@@@@@@@@; 5@@@B ,@@@@I E@N@@@
       |@@@@@@@@@: CL`  :B@N@i k@@KB@@@@@@t .N@@6 _@@@@' *@@@@@
       |@@@@@@@Q,`aB`:TT@@@@@- i@@k5@@@@@@@; 'B@@- O@d_  s@@@@@
       |@@@@@@D> `+-:BqN@@@@l `k@@@'O@@@@@@B  ;@@u -NA  k@@@@@@
       |@@@@@@d`  ,  ~@@@@@B` u@@@@+ V@@@@@@;A 4@@`'-. +@@@@@@@
       |@@@@@9_- 5@;  B@@@@A ,B@@@@N' B@@@@@\>`n@@=+>  D@@@@@@@
       |@@@@@;@I |@@6'_B@@@K ;@@@@@@: @@@@@@v ;@@@@@`  N@@@@@@@
       |@@@@BN@L v@@@B `d@@O` X@@@@D -@@@@@@s C@@@@$   t@@@@@@@
       |@@@@@@B: ?@@@@: +@@@v `B@@@B` e@@@@@s 7@@@B'`9` %@@@@@@
       |@@@@@@@@? 7@@@~  E@@8. ,@@@@C  D@@@@] ;@@@= OB' `k@@@@@
       |@@@@@@@@j ;@@B'z `@@@E  O@@@|  ^@@@B: +@@d *@@@; `@@@@@
       |@@@@@@@@+ j@@@lD  d@@+  %@@> :L`,BD- ,@@@' g@@@n '@@@@@
       |@@@@@@@@T`r@@@@B` e@9d+ >@L '@@B'-` ;~@@4 .@@@@g '@@@@@
       |@@@@@@@@@{'@@@@@?'`>BB, V|  d@@@B`  D8B@" 'B@@@@^ w@@@@
       |@@@@@@@@@+|@@@@@@BN?`_  '  ?@@@@@D' C@@N `N@@@@@6 .@@@@
       |@@@@@@@@N`N@@@@@@@@@g`  ;LsB@@@@@@@\ :@Q *@@@@@@d` K@@@
       |@@@@@@@@N'@@@@@@@@@@C  \@@@@@@@@@@@B  N@;3@@@@@@@B,`A@@
       |@@@@@@@@@,Q@@@@@@@d7.  ?@@@@@@@@@@@|- tN'V@@@@@@@@B``g@
       |@@@@@@@@@B@@@@@@@@B@L |=@@@@@@@@@@g6B:_&'|@@@@@@@@@y _@
       |@@@@@@@@@@@@@@@@@@@@I A@@@@@@@@@@@@@@d @d`B@@@@@@@@@,:@
       |@@@@@@@@@@@@@@@@@@@@D i@@@@@@@@@@@@@@Q,@n;B@@@@@@@@@t/@
       |@@@@@@@@@@@@@@@@@@@@@V,B@@@@@@@@@@@@@@$N`@@@@@@@@@@@\L@
       |@@@@@@@@@@@@@@@@@@@@@@:B@@@@@@@@@@@@@@@@e@@@@@@@@@@j'@@
       |@@@@@@@@@@@@@@@@@@@@@@jB@@@@@@@@@@@@@@@@@@@@@@@@@@@'d@@
       |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@B^@@@
       |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@4B@@""".stripMargin
    )
  }
}
