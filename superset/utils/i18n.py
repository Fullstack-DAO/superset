import humanize
import datetime

def localized_naturaltime(time: datetime, locale: str) -> str:
   if locale == "en":
       return humanize.naturaltime(time)
   humanize.i18n.activate(locale)
   naturalized = humanize.naturaltime(time)
   humanize.i18n.deactivate()
   return naturalized