# Development Notes / Observations
Daniel Matthews | A0118543

---

## Week 1
I originally planned to have the SRP authentication process be over 2 steps, but when implementing the SRP unit test I realized that my the SRP library I'm using requires the server to be proven before the client will generate it's proof. This combined with the libraries requirement for the client secret to be known before A is generated means that the authentication process requires 3 steps.

## Week 2
I have realized that I don't have anything different for a SRP test on the client compared to the server, so I am going to copy it over, and then work on my token system instead.

I have realized that for the system I am going to make Json Web Tokens (JWT) are unnecessary and would just add extra complexity to the system, so I am going to use simple tokens instead.

## Weeks 3, 4, 5
Things got a bit busy, but by the end of this week I will have account creation and account login done. I have realized that I can do end-to-end tests, but it required me to change the layout of my code a bit. Now my main.go files are just the state machine. The transitional functions and constants have been moved to engine.go files as this will let me run the functions in go's testing suite.

I have also decided that I will get rid of the specific SRP test because the authentication test is basically a super set of it anyways.

This has taken more time then I expected, so I am deciding now that I won't make a web client. If I have completed my features and have time left over, I will improve the existing client makiing the navigation more like a TUI instead of a simple option select with numbers like it is now.