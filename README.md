# Netra

> **See what your computer is doing on the network. Let an AI agent investigate what matters.**

> 🚀 **Frogtoberfest 2026**
>
> Netra is being developed as part of **Leapfrog Technology's Frogtoberfest 2026** open-source hackathon.

## The Problem

Our computers are constantly communicating with services across the internet, but most users have little visibility into what is happening.

Which application is communicating with whom?
How much data is being transferred?
Is this behavior normal?
Should something be blocked or investigated?

Existing network-monitoring tools can expose this information, but understanding raw network data often requires technical knowledge.

## The Idea

**Netra** is an open-source, local-first network intelligence agent designed to make network activity easier to understand and act on.

It will monitor application-level network activity, learn normal behavior, detect anomalies, and use an AI agent to investigate and explain what is happening.

When something unusual is detected, Netra will notify the user and provide personalized recommendations, such as blocking or filtering a domain.

The goal is to move from simply **seeing network traffic** to **understanding and responding to it**.

## How AI Powers It

AI acts as the reasoning layer of Netra.

It will:

* Detect unusual network behavior
* Investigate anomalies using available network data
* Connect activity across applications, domains, and connections
* Explain findings in simple language
* Generate personalized alerts and recommendations
* Suggest actions such as blocking or filtering traffic

The AI is intended to be a core part of the product, not simply a chatbot added to a conventional network monitor.

## Pilot Features

The initial pilot will focus on:

* 📡 Application-level network monitoring
* 🔎 Network activity and destination visibility
* 🚨 Anomaly detection
* 🤖 AI-powered investigation and explanation
* 🔔 Notifications for unusual activity
* 🎯 Personalized recommendations
* 🛡️ Domain blocking and filtering recommendations
* 🔐 Local-first network telemetry

These are our **starting features**. The project is designed to expand significantly as development progresses.

## Local-First & Privacy

Network activity can contain sensitive information.

Netra is being designed with a **local-first approach**, keeping network telemetry under the user's control and minimizing unnecessary transmission of network data to external services.

## Project Status

🚧 **Early Development**

Netra is currently at the beginning of development. The features described above represent the initial direction and pilot scope, and the implementation will evolve as we build and test the project.

## Frogtoberfest 2026

Netra is being developed as part of **Leapfrog Technology's Frogtoberfest 2026** open-source hackathon.

This repository represents the starting point of the project. We plan to expand the initial pilot into a broader network intelligence and control platform through continued development and experimentation.

## Contributing

The project is currently in its early development stage.

Contribution guidelines and development documentation will be added as the project takes shape.

Ideas, feedback, and discussions are welcome.

## License

Netra is released under the **Apache License 2.0**.

See [LICENSE](LICENSE) for the full license text.
