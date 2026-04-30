# Development Notes / Observations
Daniel Matthews | A0118543

---

## Week 1
I originally planned to have the SRP authentication process be over 2 steps, but when implementing the SRP unit test I realized that my the SRP library I'm using requires the server to be proven before the client will generate it's proof. This combined with the libraries requirement for the client secret to be known before A is generated means that the authentication process requires 3 steps.