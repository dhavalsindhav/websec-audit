# Contributing to WebSec-Audit

We love your input! We want to make contributing to WebSec-Audit as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features
- Becoming a maintainer

## Development Process

We use GitHub to host code, to track issues and feature requests, as well as accept pull requests.

### Pull Requests

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Clone the repository
git clone https://github.com/username/websec-audit.git

# Install dependencies
npm install

# Build the project
npm run build

# Run tests
npm test
```

## Code Style

Please make sure your code adheres to the existing style. We use ESLint and Prettier for code formatting:

```bash
# Check for linting issues
npm run lint

# Format code
npm run format
```

## Testing

We have a comprehensive test suite. Please add tests for any new functionality:

```bash
# Run all tests
npm test

# Run tests in watch mode during development
npm run test:watch
```

## License

By contributing, you agree that your contributions will be licensed under the project's MIT License.
