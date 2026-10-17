# Onekey

BCIT Capstone Project. A Golang based zero knowledge password manager with a terminal client.

I am currently rewriting the project in Rust on a private repo. I enjoyed working with Go on the project, but ran into some frustration with the amount of boilerplate I had to write and figured I would give rust a try as it and Go are both languages I would consider for a hobby project.

After I finish the Rust rewrite, I plan to do a final rewrite using Gleam. I realized that building a web client and other web features would be a large undertaking with friction between the Go backend and js/ts frontend. Unfortunately using something like htmx isn't really applicable here as it is more focused on server based processing, and this project requires a significant amount of local processing for on device encryption/decryption and key derivation.

Gleam comes in as a language that can be compiled to Javascript and/or Erlang, so I can use it for both my backend and frontend, and it should have fewer sissues then trying to mix javascript and a language like Go or Rust.

# Demo

![Demo Video](OneKey_Demo.mp4)
