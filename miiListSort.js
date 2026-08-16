export const MII_LIST_SORT_VALUES = Object.freeze([
  "alphabetical",
  "trending",
  "top",
  "latest",
]);

export const MII_LIST_SORT_DIRECTION_VALUES = Object.freeze(["asc", "desc"]);

const MII_LIST_SORT_SET = new Set(MII_LIST_SORT_VALUES);
const MII_LIST_SORT_ALIASES = new Map([
  ["popular", "top"],
  ["recent", "latest"],
]);
const MII_LIST_SORT_DIRECTION_SET = new Set(MII_LIST_SORT_DIRECTION_VALUES);
const MII_LIST_SORT_DIRECTION_ALIASES = new Map([
  ["ascending", "asc"],
  ["descending", "desc"],
]);
const TRENDING_TIME_DECAY_EXPONENT = 1.25;

export function normalizeMiiListSort(value, fallback = "top") {
  const normalizedFallback = MII_LIST_SORT_SET.has(
    String(fallback || "").toLowerCase()
  )
    ? String(fallback).toLowerCase()
    : "top";
  const requested = typeof value === "string" ? value.trim().toLowerCase() : "";

  if (MII_LIST_SORT_SET.has(requested)) return requested;
  return MII_LIST_SORT_ALIASES.get(requested) || normalizedFallback;
}

export function normalizeMiiSearchSort(value, hasTextSearch = false) {
  const requested = typeof value === "string" ? value.trim().toLowerCase() : "";

  if (hasTextSearch && (!requested || requested === "relevance")) {
    return "relevance";
  }
  return normalizeMiiListSort(requested, "top");
}

export function getDefaultMiiListSortDirection(value) {
  const requested = typeof value === "string" ? value.trim().toLowerCase() : "";
  const sort =
    requested === "relevance" ? "relevance" : normalizeMiiListSort(requested);

  return sort === "alphabetical" ? "asc" : "desc";
}

export function normalizeMiiListSortDirection(value, sort = "top") {
  const requested = typeof value === "string" ? value.trim().toLowerCase() : "";

  if (MII_LIST_SORT_DIRECTION_SET.has(requested)) return requested;
  return (
    MII_LIST_SORT_DIRECTION_ALIASES.get(requested) ||
    getDefaultMiiListSortDirection(sort)
  );
}

function resolveSortContext(value, nowOrDirection, direction) {
  const sort = normalizeMiiListSort(value);
  const directionInNowPosition = typeof nowOrDirection === "string";
  const rawNow = directionInNowPosition ? Date.now() : nowOrDirection;
  const rawDirection = directionInNowPosition ? nowOrDirection : direction;

  return {
    sort,
    direction: normalizeMiiListSortDirection(rawDirection, sort),
    now: Number.isFinite(Number(rawNow)) ? Number(rawNow) : Date.now(),
  };
}

export function getMiiListSortStages(
  value,
  nowOrDirection = Date.now(),
  direction
) {
  const context = resolveSortContext(value, nowOrDirection, direction);
  const { sort } = context;
  const primaryDirection = context.direction === "asc" ? 1 : -1;

  if (sort === "alphabetical") {
    return [
      {
        $addFields: {
          listSortName: {
            $toLower: {
              $let: {
                vars: {
                  metaName: {
                    $trim: { input: { $ifNull: ["$meta.name", ""] } },
                  },
                  legacyName: { $trim: { input: { $ifNull: ["$name", ""] } } },
                },
                in: {
                  $cond: [
                    { $ne: ["$$metaName", ""] },
                    "$$metaName",
                    "$$legacyName",
                  ],
                },
              },
            },
          },
        },
      },
      {
        $sort: {
          listSortName: primaryDirection,
          uploadedOn: -1,
          _id: -1,
        },
      },
    ];
  }

  if (sort === "trending") {
    const normalizedNow = context.now;
    return [
      {
        $addFields: {
          listAgeHours: {
            $max: [
              0,
              {
                $divide: [
                  {
                    $subtract: [
                      normalizedNow,
                      { $ifNull: ["$uploadedOn", normalizedNow] },
                    ],
                  },
                  1000 * 60 * 60,
                ],
              },
            ],
          },
        },
      },
      {
        $addFields: {
          listHotness: {
            $divide: [
              { $ifNull: ["$votes", 0] },
              {
                $pow: [
                  { $add: ["$listAgeHours", 2] },
                  TRENDING_TIME_DECAY_EXPONENT,
                ],
              },
            ],
          },
        },
      },
      {
        $sort: {
          listHotness: primaryDirection,
          uploadedOn: -1,
          _id: -1,
        },
      },
    ];
  }

  if (sort === "latest") {
    return [{ $sort: { uploadedOn: primaryDirection, _id: -1 } }];
  }

  return [
    {
      $sort: {
        votes: primaryDirection,
        uploadedOn: -1,
        _id: -1,
      },
    },
  ];
}

function getDisplayName(mii) {
  return String(mii?.meta?.name || mii?.name || "").trim();
}

function getTrendingScore(mii, now) {
  const uploadedOn = Number(mii?.uploadedOn);
  const ageHours = Number.isFinite(uploadedOn)
    ? Math.max(0, (now - uploadedOn) / (1000 * 60 * 60))
    : 0;
  return (
    Number(mii?.votes || 0) /
    Math.pow(ageHours + 2, TRENDING_TIME_DECAY_EXPONENT)
  );
}

export function compareMiiListItems(
  left,
  right,
  value,
  nowOrDirection = Date.now(),
  direction
) {
  const context = resolveSortContext(value, nowOrDirection, direction);
  const { sort } = context;
  const directionMultiplier = context.direction === "asc" ? 1 : -1;
  let difference = 0;

  if (sort === "alphabetical") {
    difference =
      getDisplayName(left).localeCompare(getDisplayName(right), undefined, {
        sensitivity: "base",
        numeric: true,
      }) * directionMultiplier;
  } else if (sort === "trending") {
    difference =
      (getTrendingScore(left, context.now) -
        getTrendingScore(right, context.now)) *
      directionMultiplier;
  } else if (sort === "latest") {
    difference =
      (Number(left?.uploadedOn || 0) - Number(right?.uploadedOn || 0)) *
      directionMultiplier;
  } else {
    difference =
      (Number(left?.votes || 0) - Number(right?.votes || 0)) *
      directionMultiplier;
  }

  return (
    difference ||
    Number(right?.uploadedOn || 0) - Number(left?.uploadedOn || 0) ||
    String(right?._id || right?.id || "").localeCompare(
      String(left?._id || left?.id || "")
    )
  );
}

export function sortMiiListItems(
  items,
  value,
  nowOrDirection = Date.now(),
  direction
) {
  const context = resolveSortContext(value, nowOrDirection, direction);

  return Array.isArray(items)
    ? [...items].sort((left, right) =>
        compareMiiListItems(
          left,
          right,
          context.sort,
          context.now,
          context.direction
        )
      )
    : [];
}
