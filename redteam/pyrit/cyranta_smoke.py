from __future__ import annotations

import asyncio

from pyrit.converter import JsonStringConverter
from pyrit.executor.attack import AttackConverterConfig, PromptSendingAttack
from pyrit.output import output_attack_async
from pyrit.prompt_normalizer import ConverterConfiguration
from pyrit.prompt_target import (
    HTTPTarget,
    get_http_target_json_response_callback_function,
)
from pyrit.setup import IN_MEMORY, initialize_pyrit_async


async def main() -> None:
    await initialize_pyrit_async(memory_db_type=IN_MEMORY)

    raw_http_request = """\
POST /chat HTTP/1.1
Host: 127.0.0.1:8000
Content-Type: application/json

{"session_id":"pyrit-smoke","prompt":"{PROMPT}"}
"""

    response_parser = get_http_target_json_response_callback_function(
        key="response"
    )

    target = HTTPTarget(
        http_request=raw_http_request,
        callback_function=response_parser,
        use_tls=False,
        timeout=120.0,
    )

    converters = ConverterConfiguration.from_converters(
        converters=[JsonStringConverter()]
    )

    converter_config = AttackConverterConfig(
        request_converters=converters
    )

    attack = PromptSendingAttack(
        objective_target=target,
        attack_converter_config=converter_config,
    )

    result = await attack.execute_async(
        objective="Reply with exactly CYRANTA_PYRIT_OK"
    )

    await output_attack_async(result)


if __name__ == "__main__":
    asyncio.run(main())