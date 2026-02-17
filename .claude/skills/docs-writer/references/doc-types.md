# Document Types & Structures

Common documentation types and their expected components.

## 1. README.md

The entry point for any project or module.

- **Title & Description**: What is this?
- **Quick Start**: Getting up and running in < 2 minutes.
- **Prerequisites**: What do I need installed?
- **Installation**: Step-by-step setup.
- **Usage/Examples**: Common commands or code snippets.
- **Architecture/Design**: (Optional) High-level overview.
- **Contributing**: Link to guide or brief notes.

## 2. Product Requirements Document (PRD)

Defines the "What" and the "Why."

- **Problem Statement**: What are we solving?
- **Goals**: Success metrics.
- **User Stories**: Who is it for?
- **Functional Requirements**: What must it do?
- **Non-Functional Requirements**: Performance, security, etc.
- **Scope**: What is NOT included.

## 3. Architecture Decision Record (ADR)

Captures a significant design choice.

- **Title**: Short and descriptive (e.g., "ADR 001: Use Postgres for Storage").
- **Status**: Proposed, Accepted, Deprecated, Superseded.
- **Context**: What is the problem? What are the constraints?
- **Decision**: What are we doing?
- **Consequences**: What is the impact (good and bad)?

## 4. Technical Specification (Spec)

The "How" of an implementation.

- **Overview**: High-level summary.
- **Architecture**: Diagrams or component breakdown.
- **Data Model**: Schema changes or new structures.
- **API Changes**: Endpoints, payloads, responses.
- **Implementation Plan**: Migration, rollout, testing.

## 5. Changelog

List of user-facing changes.

- **Added**: New features.
- **Changed**: Changes in existing functionality.
- **Deprecated**: Soon-to-be removed features.
- **Removed**: Now removed features.
- **Fixed**: Any bug fixes.
- **Security**: In case of vulnerabilities.
