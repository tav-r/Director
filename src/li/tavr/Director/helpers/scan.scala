package li.tavr.Director.helpers

import burp.IParameter
import scala.language.postfixOps

def redirect_params(params: List[IParameter]): List[IParameter] = {
  val pattern = ("(back|go|goto|goback|return|returnto|return_to|returnurl|returnuri|return_url"+
    "|return_path|redi|redirect|redirect_url|redirect_uri|r_url|rurl|locationurl|locati"+
    "onuri|next|dest|destination|checkout_url|continue|url)").r

  params.filter(p => pattern.findAllIn(p.getName.toLowerCase) nonEmpty)
}