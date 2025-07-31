import asyncio
from aegis_ai.agents import rh_feature_agent
from aegis_ai.features import cve


async def main():
    feature = cve.SuggestImpact(rh_feature_agent)
    result = await feature.exec("CVE-2021-47645")
    print(result.output.model_dump_json(indent=2))


if __name__ == "__main__":
    asyncio.run(main())