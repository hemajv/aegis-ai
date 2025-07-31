import asyncio
from aegis_ai.agents import rh_feature_agent
from aegis_ai.features import cve
import json
import csv

async def main(file_path, output_file_path):
    all_results = []

    try:
        with open(file_path, 'r') as f:
            cve_ids = [line.strip() for line in f if line.strip()] # Read and clean each line
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return
    
    print(f"Processing {len(cve_ids)} CVEs from {file_path}...")

    feature = cve.SuggestImpact(rh_feature_agent)

    for cve_id in cve_ids:
        print(f"\n--- Processing CVE: {cve_id} ---")
        try:
            result = await feature.exec(cve_id)
            json_result = result.output.model_dump_json(indent=2)
            result_dict = json.loads(json_result)
            final_dict = {"cve_id":result_dict.get('cve_id', cve_id), "suggested_impact":result_dict.get('impact', 'N/A')}
            all_results.append(final_dict)
            print(f"Result for {cve_id}: {final_dict}")
        except Exception as e:
            print(f"Error processing {cve_id}: {e}")
            all_results.append({"cve_id": cve_id, "suggested_impact": "Error", "error_details": str(e)})

    print("\n--- All CVEs Processed ---")

    # --- Save the results to a CSV file ---
    if all_results: # Ensure there are results to write
        fieldnames = ["cve_id", "suggested_impact"]

        try:
            with open(output_file_path, 'w', newline='') as csvfile:
                # Use DictWriter, which maps dictionaries to rows
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader() # Write the header row
                writer.writerows(all_results) # Write all data rows

            print(f"\nAll results saved to {output_file_path}")
        except IOError as e:
            print(f"Error saving results to {output_file_path}: {e}")
    else:
        print(f"\nNo results to save to {output_file_path}.")
    
    return all_results

if __name__ == "__main__":
    asyncio.run(main(file_path="kernel_cve_ids.txt", output_file_path="kernel_cves_aegis_predicted.csv"))