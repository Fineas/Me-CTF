     ______          __     ______      __          __________________
    / ____/___  ____/ /__  / ____/___ _/ /____     / ____/_  __/ ____/
   / /   / __ \/ __  / _ \/ / __/ __ `/ __/ _ \   / /     / / / /_
  / /___/ /_/ / /_/ /  __/ /_/ / /_/ / /_/  __/  / /___  / / / __/
  \____/\____/\__,_/\___/\____/\__,_/\__/\___/   \____/ /_/ /_/  2019

  Player = FeDEX, Rank: 9, Category: Junior, Country: Romania

  [*] Challenges Solved: 3
      [>] MIC check
      [>] 20000
      [>] algo_auth

  [ ################ ]
  [ #1 ] - MIC check
  [ ################ ]

  We are asked to decode the following string: 9P&;gFD,5.BOPCdBl7Q+@V’1dDK?qL
  My first tought was that it might be some base64 encoding, but because of the diversity of characters, it couldn't be.
  Next idea was to check base85, which indeed turned out to be the good one.

  FLAG = Let the hacking begins ~

  [ ################ ]
  [ #2 ] - 20000
  [ ################ ]

  We've been given a binary and 20000 libraries ( .so )
  After a quick analysis, the binary seems to be pretty straight-forward.
  First, ask for user input ( %d ), then open the coresponding library.
  (For example, if I were to enter 1337, the program would load lib_1337.so)
  Next, the binary was calling the test function from the shared object.
  This means I had no choice but to open a few libraries and see what the test function is about and how is changes from file to file.
  It turned out to be only 3 types of libraries. 2 of them containing a filter function, while the 3rd one was like a wrapper, calling both filter funcitons.
  Now everything was clear, I had to call the wrapper function, pass both filters and in the end execute an "arbitrary command"
  The only thing left to do was to figure out a way to bypass the filters and still execute an arbitrary comand.
  Let's have a look at the restricted inputs: ['bin', 'sh', 'bash', 'v', 'm', 'p', 'd', 'n', 'f', 'l', 'g', ';', '*', '`', '&', '$', '>', '<', 'r', '|']
  At this point getting a shell seems impossible. But characters "c", "a", "t" are free to use (we will keep this in mind)
  They way out input is passed to system looks like this: system("ls \" %s \" ")
  We cannot avoit executing ls, that why we wanna make it quick.
  So out payload starts to look like this: ls " . " All good so far
  Moving forward we would like to cat the flag as a next instruction. Jumping to the next instruction should be easy, just pass an end line \n and type cat
  Here comes the challenging part: find a way to print the flag considering that characters f, l, g are forbidden as well as *
  After a bit of thinking, I remembered we can substitute any characters with ? Great!
  so this is how my payload looks like: . " \n cat ./??a? # ".
  After getting the flag, I realised I could use this tecnique to get a shell as well: ." \n /bi?/ba?h # ".

  FLAG = Are_y0u_A_h@cker_in_real-word?
  SCRIPT = solve_binaries.py


  [ ################ ]
  [ #3 ] - algo_auth
  [ ################ ]

  For this challenge we only got an IP and a PORT.
  Connecting to it showed some instructions and a game. It was straight forward what we had to do. Write some code that finds the shortest path from the left column to the right one.
  Easy-peasy. Wrote a few lines of code to do this for all 100 levels using dynamic programming and after this I got the message: @@@@@ Congratz! Your answers are an answer
  Entered it as the flag and it was wrong. Strange?
  I then printed the solutions for the program and everything became clear:
  [82,107,120,66,82,121,65,54,73,71,99,119,77,71,57,118,84,48,57,107,88,50,111,119,81,105,69,104,73,86,57,102,88,51,86,117,89,50,57,116,90,109,57,121,100,68,82,105,98,71,86,102,88,51,77,122,89,51,86,121,97,88,82,53,88,49,57,112,99,49,57,102,98,106,66,48,88,49,56,48,88,49,57,122,90,87,78,49,99,109,108,48,101,83,69,104,73,83,69,104,]
  All values are ascii values
  I quickly turned them into chars:
  RkxBRyA6IGcwMG9vT09kX2owQiEhIV9fX3VuY29tZm9ydDRibGVfX3MzY3VyaXR5X19pc19fbjB0X180X19zZWN1cml0eSEhISEh
  And .... no flag yet. I decoded the base64 and got the flag.
  (I also realised this problem could have been solved using pure bf because the range for values is 48-122)

  FLAG = g00ooOOd_j0B!!!___uncomfort4ble__s3curity__is__n0t__4__security!!!!!

  [ ########################## ]
    [ # ] - Final Thoughts
  [ ########################## ]

  Overall I enjoyed the CTF. The only issue was that on the main page there was a count down that said: Competition begins at 09:00 EET.
  I got to sleep, and when I woke up for the competition, there were only 5h left :(
  After the competition ended for juniors I managed to solve: 4 more chals.

  I'm enthusiastic and looking forward to attend the finals and solve some high quality pwns.
  Thank You for another great CTF!
