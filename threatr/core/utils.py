from threatr.core.models import Event


def merge_events(event_list: list[Event]):
    sorted_events = sorted(event_list, key=lambda x: x.first_seen)
    merged = []
    dropped = []
    for event in sorted_events:
        # If the list of merged intervals is empty or if the current interval does not overlap with the previous one,
        # simply add it to the merged list
        if not merged or event.first_seen.date() > merged[-1].last_seen.date():
            merged.append(event)
        else:
            # If the current interval overlaps with the previous one, merge them by updating the end value of the last interval
            merged[-1].last_seen = max(merged[-1].last_seen, event.last_seen)
            merged[-1].count += event.count
            dropped.append(event)
    return merged, dropped


def merge_similar_events(event_list: list[Event]):
    buckets = {}
    merged_events = []
    for event in event_list:
        key = f'{event.name}-{event.involved_entity.name}-{event.attributes.get("source_vendor", "")}'
        if key not in buckets:
            buckets[key] = []
        buckets[key].append(event)

    for key, events in buckets.items():
        merged, dropped = merge_events(events)
        for event in dropped:
            event.delete()
        for event in merged:
            event.save()
            merged_events.append(event)
    return merged_events
