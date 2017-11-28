import feedparser

class HpHostsFeed(object):
    '''HpHostsFeed class'''
    def __init__(self, category='PSH'):
        self.category = category
        self.feed_url = 'https://hosts-file.net/rss.asp?class=' + category
        self.hphosts_feed = False
        self.main()

    def main(self):
        self.hphosts_feed = feedparser.parse(self.feed_url)

    @property
    def entries(self):
        entries = self.hphosts_feed.entries
        return entries
