FROM python:3.12-slim-bookworm

WORKDIR /profilehound

# Enable unbuffered stdout and stderr for Python, ensuring logs are printed in real-time
ENV PYTHONUNBUFFERED=1

# Copy the source code
COPY . .

# Install the package and its dependencies using pip
RUN pip install --no-cache-dir .

# Set the entrypoint to the profilehound script
ENTRYPOINT ["profilehound"]
