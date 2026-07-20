WRITEUP Securing GreenThumb

This report explains the five security holes I fixed. For each one I say what the bug was, the attack I used to prove it, the fix I made, and what the fix does not protect against. The app runs with npm install and npm start on port 3000. Running npm run exploit reports SECURE for all five, and the site still works (search, login, comments, and the note banner all function).


FIX 1 SQL injection (logging in without a password)

The bug was that the login code glued my typed in username and password straight into the database query, so my text became part of the query instead of just being data.

The attack was typing (curator' --) as the username. The single quote closes the username early, and the two dashes start a comment that makes the database ignore the rest of the line, including the password check. So it just logged me in as curator with no password.

The fix was using a parameterized query, which sends the query and the values separately using question mark placeholders (username = ? and password = ?). Now the database treats my input as plain data, so typing (curator' --) just searches for a user with that exact name, finds nobody, and rejects the login.

What it does not fix is weak passwords, brute force guessing, or the plain text passwords (that part was left in on purpose).


FIX 2 SQL injection (stealing data with UNION and an unsafe sort)

The bug was the same gluing problem in the search page, in two places (the search word and the sort option were both pasted into the query).

The attack for the search word was (zzznomatch%' UNION SELECT id, username, password, 'x' FROM users -- ). UNION bolts a second query onto the first. The real search returns four columns so my UNION returns four too (I padded the last one with 'x'). This pulled every username and password out of the users table into the search results.

The fix was two things. For the search word I used a question mark placeholder so it is treated as plain data. For the sort option I could not use a placeholder (those only work for values, not column names or words like DESC), so I made an allow list of the only sort choices the app accepts, and anything not on the list falls back to a safe default.

What it does not fix is that the allow list only works because there are just a few valid sort options, and it does not control who is allowed to see which data.


FIX 3 Reflected XSS in search

The bug was that the search page printed my search word back onto the page without cleaning it, so if I typed HTML the browser treated it as real HTML.

The attack was searching for (<img src=x onerror=alert(document.domain)>). The image cannot load, which triggers the onerror part, which runs my JavaScript. I used an image trick because a plain script tag added this way usually will not run.

The fix was a small escapeHtml function that turns dangerous characters like the angle brackets into harmless text versions, so my payload shows up as plain visible text instead of running.

What it does not fix is other situations, because this cleaning is only right for putting text into HTML (a link, a script block, or CSS would each need different handling).


FIX 4 Stored XSS in comments and DOM based XSS in the note banner

The first bug was that comments were saved exactly as typed and shown to everyone with no cleaning. This is worse than reflected XSS because the victim only has to look at the page, not click a special link.

The attack was posting a comment containing (<img src=x onerror="alert('...')">), which then ran in the browser of everyone who viewed that listing.

The fix was running both the comment text and the author name through my escapeHtml function so any HTML shows as plain text.

The second bug was that the page let you put a note in the web address (like #note=hello) and showed it using innerHTML, which treats its input as HTML. This one never even reaches the server, it happens entirely in the browser.

The attack was visiting (/listing/1#note=<img src=x onerror=alert('dom-xss')>), which ran my JavaScript.

The fix was changing the code to use textContent instead of innerHTML, because textContent shows the value as plain text and never runs it as HTML.

What it does not fix is that the bad comment is still stored in the database, and the safe code fix only covers this one spot (any other unsafe spot would need the same treatment).


FIX 5 Cookie safety flags and a Content Security Policy

The bug was that the login cookie had no protective settings and the app sent no Content Security Policy, so JavaScript on the page could read the session cookie and steal a login, and the browser would run injected scripts.

The attack was the check script logging in and seeing the cookie had no HttpOnly and no SameSite, and there was no CSP header.

The fix was adding HttpOnly to the cookie (so JavaScript can no longer read it and an XSS cannot steal the session) and SameSite=Strict (so the browser will not send the cookie on requests from other sites), plus Secure when over HTTPS. I also added a Content Security Policy that only allows scripts from the app itself, so an injected onerror handler will not run even if some XSS slipped through.

What it does not fix is the injection itself. These are backup protections (CSP reduces the damage but good encoding is still the real fix, and HttpOnly protects the cookie but does not stop the XSS).


One thing I noticed but did not change

The passwords are stored in plain text in the database seed file, which is dangerous in a real app (passwords should be a slow salted hash like bcrypt or argon2). The assignment said to leave this on purpose, so I did, but I wanted to note that I saw it.
