import re
import art

with open("flag.txt") as f:
	flag = f.readline()
	assert(flag[0:4]=="INS{" and flag[-1]=="}")
	content = flag[4:-1]
	assert(re.search(r'^[A-Z1-9_]*$', content))
	assert(content.count("_") == 2)
	content = content.replace("_","\n")


def mergeLines(line1,line2):
	line = list(map(lambda xy: " " if xy[0] == xy[1] else "#", zip(line1, line2)))
	return ''.join(line)


def mergeText(text1, text2):
	a = text1.split("\n")
	b = text2.split("\n")
	c = []
	for j in range(25):
		c.append(mergeLines(a[j],b[j]))
	return '\n'.join(c) 


i = 0
while i<3:
	text = art.text2art(content, font="rnd-medium", chr_ignore=False)
	if re.search(r'^[ #\n]*$', text) and text.count('\n') == 24:
		if i == 0:
			res = text
		else:
			res = mergeText(res,text)
		i = i+1

print(res)
	