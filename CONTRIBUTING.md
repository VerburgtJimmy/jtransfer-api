# Contributing to JTransfer API

Thank you for your interest in contributing to JTransfer API! This document provides guidelines and instructions for contributing.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/jtransfer-api.git`
3. Create a new branch: `git checkout -b feature/your-feature-name`
4. Install dependencies: `bun install`
5. Set up your environment variables (see README.md)

## Development

```bash
# Start development server
bun run dev

# Run database migrations
bun run db:push
```

## Code Style

- Use TypeScript for all new code
- Follow existing code patterns and conventions
- Use meaningful variable and function names
- Add comments for complex logic

## Commit Messages

We follow conventional commits. Format your commit messages as:

```
type(scope): description

[optional body]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Examples:
- `feat(upload): add file size validation`
- `fix(download): handle expired transfers correctly`
- `docs(readme): update installation instructions`

## Pull Requests

1. Update documentation if needed
2. Make sure your code follows the existing style
3. Write a clear PR description explaining your changes
4. Link any related issues

## Reporting Issues

When reporting issues, please include:
- A clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Your environment (OS, Bun version, etc.)

## Security

If you discover a security vulnerability, please do NOT open a public issue. Instead, email the maintainers directly.

## Questions?

Feel free to open an issue for any questions about contributing.
