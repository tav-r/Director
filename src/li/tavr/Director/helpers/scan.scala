package li.tavr.Director.helpers

import burp.IParameter
import scala.language.postfixOps

def redirectParams(params: List[IParameter]): List[IParameter] = {
  val pattern = ("^(back|go|goto|goback|return|returnto|return_to|returnurl|returnuri|return_url"+
    "|return_path|redi|redirect|redirect_url|redirect_uri|r_url|rurl|locationurl|locati"+
    "onuri|next|dest|destination|checkout_url|continue|url|rurl)$").r

  params.filter(p => pattern.findAllIn(p.getName.toLowerCase) nonEmpty)
}

def javaScriptPatterns(body: String): List[String] = {
  val pattern = ("((|\\w|\\.|;|\\})(location|location\\.host|location\\.hostname|location\\.href|location\\.pathname|location\\.search|"+
    "location\\.protocol|element\\.srcdoc)\\w*=\\w*[^=\"'\\w]|(location\\.assign\\(|location\\.replace\\(|open\\(|"+
    "XMLHttpRequest\\.open\\(|XMLHttpRequest\\.send\\(|jQuery\\.ajax\\(|\\$\\.ajax\\()[^\"'])").r

  pattern findAllIn(body) toList
}
