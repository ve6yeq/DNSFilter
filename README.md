DNSFilter
=========

Filter DNS requests as a brute force way of cutting down on the amount of
advertisements when web browsing by intercepting them using the Darwin ipfw
packet divert functionality and then send back fake not found responses to
requests that match provided blacklists.
